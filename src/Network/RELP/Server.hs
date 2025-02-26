-- | RELP (Reliable Event Logging Protocol) simple server
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MonoLocalBinds #-}
module Network.RELP.Server
  (
    -- * Running a standalone RELP server
    RelpMessageHandler
  , runRelpServer
  , runTLSServer, runTLSServer'
  , RelpFlow
  , buildRelpServerHandle
  )
  where

import Prelude hiding (getContents, take)
import Network.Socket (PortNumber, AddrInfo(..),
  AddrInfoFlag(..), SocketType(..), SocketOption(..))
import qualified Network.Socket as S
import Network.Socket.ByteString.Lazy ( getContents, sendAll )
import qualified Data.ByteString as B
import Network.Simple.TCP.TLS
import Network.TLS
import Data.X509.CertificateStore
import Data.Attoparsec.ByteString (parseOnly, string, take,
  takeWhile1, word8, many', Parser)
import qualified Data.Attoparsec.ByteString.Lazy as LBP
import qualified Data.ByteString.Lazy.Char8 as B8
import Data.ByteString (ByteString)
import Data.ByteString.UTF8 (toString)
import Data.Functor ( ($>), (<&>), void )
import Control.Applicative ( Alternative((<|>)) )
import Control.Monad (forever)
import Control.Monad.IO.Class

import Control.Monad.Catch
import System.IO hiding (getContents)
import qualified Control.Exception as E

-- | Message handler callback.
type RelpMessageHandler m = Monad m => 
  SockAddr -- ^ Client connection address
  -> ByteString -- ^ Log message
  -> m Bool -- ^ Reject message (reply error RSP) if False

data RelpCommand = RelpRSP | RelpOPEN | RelpSYSLOG | RelpCLOSE
  | RelpCommand ByteString
  deriving (Show, Eq)

data RelpMessage = RelpMessage
  { relpTxnr :: Int
  , relpCommand :: RelpCommand
  , relpData :: ByteString
  } deriving (Show, Eq)

type RelpOffers = [(ByteString, ByteString)]

class RelpFlow a where
  flowRecv :: (MonadMask m, MonadIO m) => a -> m B8.ByteString
  flowSend :: (MonadMask m, MonadIO m) => a -> B8.ByteString -> m ()
  flowClose :: (MonadMask m, MonadIO m) => a -> m ()

instance RelpFlow Socket where
  flowRecv = liftIO . getContents
  flowSend s = liftIO . sendAll s
  flowClose = liftIO . S.close

instance RelpFlow Context where
  flowRecv = fmap B8.fromStrict . recvData
  flowSend = sendData
  flowClose = bye

-- | Provides a simple RELP server.
runRelpServer :: PortNumber -> RelpMessageHandler IO -> IO ()
runRelpServer portnum = runTCPServer Nothing portnum . buildRelpServerHandle where
  runTCPServer mhost port server = withSocketsDo $ do
      addr <- resolve
      E.bracket (open addr) S.close loop
    where
      resolve = do
          let hints = S.defaultHints {
                  addrFlags = [AI_PASSIVE]
                , addrSocketType = Stream
                }
          head <$> S.getAddrInfo (Just hints) mhost (Just $ show port)
      open addr = E.bracketOnError (S.openSocket addr) S.close $ \sock -> do
          S.setSocketOption sock ReuseAddr 1
          S.withFdSocket sock S.setCloseOnExecIfNeeded
          S.bind sock $ addrAddress addr
          S.listen sock 1024
          return sock
      loop sock = forever $ E.bracketOnError (S.accept sock) (S.close . fst)
          $ \(conn, peer) -> void $
              E.finally (server conn peer) (S.gracefulClose conn 5000)

-- | Provides a simple TLS RELP server.
runTLSServer' :: (MonadIO m, MonadMask m) => FilePath -> FilePath -> FilePath
              -> ServiceName -> (SockAddr -> ByteString -> m Bool) -> m ()
runTLSServer' fca fcr fky snm cb = liftIO lcrd >>= \cr ->
  liftIO (readCertificateStore fca) >>= \ca ->
  runTLSServer (makeServerParams cr ca) HostAny snm cb where
    lcrd = credentialLoadX509Chain fcr [fca] fky <&> either (error . show) id

-- | Provides a TLS RELP server
runTLSServer :: (MonadMask m, MonadIO m) => ServerParams -> HostPreference
             -> String -> RelpMessageHandler m -> m ()
runTLSServer params hostprefs servicename server = srv where
  srv = listen hostprefs servicename (\(sock, _peer) -> accept params sock open)
  open (ctx, peer) = do
    liftIO (hPutStrLn stderr (" …" <> show peer))
    buildRelpServerHandle server ctx peer

-- | Build relp messages handler.
buildRelpServerHandle :: (MonadIO m, MonadMask m, RelpFlow sock)
                      => RelpMessageHandler m -- ^ Message handler
                      -> sock -- ^ Server socket
                      -> SockAddr -- ^ Client address
                      -> m () -- ^ Never returns
buildRelpServerHandle cb = handleMessage where
  handleMessage sock srcAddr = do
    status <- flowRecv sock >>= processMessage sock srcAddr
    if status then handleMessage sock srcAddr else flowClose sock

  processMessage sock srcAddr = parseLazy_ err process relpParser
    where
    err e = liftIO (hPutStrLn stderr ("ERROR: parser: " ++ show e) >> return False)

    process msg@RelpMessage{ relpCommand = RelpOPEN, relpData = txt } = do
      let offers = parse_ (const []) id relpOffersParser txt
      -- NOTE only version 0 supported!
      let versionValid = (Just "0" ==) $ lookup "relp_version" offers
      -- TODO FIXME check commands offer?
      if versionValid then do
          relpRsp sock msg $ "200 OK "
            ++ "relp_version=0\nrelp_software=hsRELP\ncommands="
            ++ maybe "syslog" toString (lookup "commands" offers)
          return True
        else relpNAck sock msg "unsupported RELP version" >> return False

    process msg@RelpMessage{ relpCommand = RelpSYSLOG, relpData = txt } = do
      status <- cb srcAddr txt
      if status then relpAck sock msg else relpNAck sock msg "rejected"
      return status

    process msg = do
      liftIO (hPutStrLn stderr ("ERROR: strange message command: " ++ show msg))
      relpNAck sock msg "unexpected message command"
      return False

relpParser :: Parser RelpMessage
relpParser = do
  txnr <- decimal <* space
  command <- parseCommand <* space
  datalen <- decimal <* space
  content <- take datalen
  return $ RelpMessage txnr command content
  where
  decimal :: Integral a => Parser a
  decimal = B.foldl' step 0 `fmap` takeWhile1 isDecimal where
    step a c = a * 10 + fromIntegral (c - 48)
    isDecimal c = c >= 48 && c <= 57
  space = word8 32
  parseCommand =
    string "syslog" $> RelpSYSLOG
    <|> string "close" $> RelpCLOSE
    <|> string "open" $> RelpOPEN
    <|> string "rsp" $> RelpRSP
    <|> RelpCommand <$> takeWhile1 (/= 32)

relpOffersParser :: Parser RelpOffers
relpOffersParser = many' $ pair <* word8 sep
  where
  sep = 10 -- \n
  der = 61 -- '='
  pair = liftA2 (,)
    (takeWhile1 (\c-> c /= der && c /= sep))
    (word8 der *> takeWhile1 (/= sep) <|> return "")

relpRsp :: (MonadIO m, MonadMask m, RelpFlow s) => s -> RelpMessage -> String -> m ()
relpRsp sock msg reply = flowSend sock mkReply
  -- putStrLn $ prettyHex $ B8.toStrict mkReply
  where
  mkReply = B8.pack $ show (relpTxnr msg) ++ " rsp "
    ++ show (length reply) ++ " " ++ reply ++ "\n"

relpAck :: (MonadIO m, MonadMask m, RelpFlow s) => s -> RelpMessage -> m ()
relpAck sock msg = relpRsp sock msg "200 OK"

relpNAck :: (MonadIO m, MonadMask m, RelpFlow s) => s -> RelpMessage -> String -> m ()
relpNAck sock msg err = relpRsp sock msg $ "500 " ++ err

-- just shortcuts
parse_ :: (String -> c) -> (b -> c) -> Parser b -> ByteString -> c
parse_ err ok p = either err ok . parseOnly p

parseLazy_ :: (String -> c) -> (b -> c) -> Parser b -> B8.ByteString -> c
parseLazy_ err ok p = either err ok . LBP.eitherResult . LBP.parse p

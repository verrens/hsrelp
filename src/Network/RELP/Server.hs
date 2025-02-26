-- | RELP (Reliable Event Logging Protocol) simple server
{-# LANGUAGE OverloadedStrings, RecordWildCards, ScopedTypeVariables #-}
module Network.RELP.Server
  (
    -- * Running a standalone RELP server
    RelpServerParams(..)
  , runRelpServer
  , runRelpTLSServer, runRelpTLSServer'
  , RelpFlow(..)
  , buildRelpServerHandle
  )
  where

import Prelude hiding (getContents, take)
import Network.Socket (PortNumber, AddrInfo(..),
  AddrInfoFlag(..), SocketType(..), SocketOption(..))
import qualified Network.Socket as S
import Network.Socket.ByteString.Lazy ( getContents, sendAll )
import qualified Data.ByteString as B
import Network.TLS
import Network.Simple.TCP.TLS
import Data.X509.CertificateStore
import Data.Attoparsec.ByteString (parseOnly, string, take,
  takeWhile1, word8, many', Parser)
import qualified Data.Attoparsec.ByteString.Lazy as LBP
import qualified Data.ByteString.Lazy.Char8 as B8
import Data.Default
import Data.ByteString (ByteString)
import Data.ByteString.UTF8 (toString)
import Data.Functor ( ($>), (<&>), void )
import Control.Applicative ( Alternative((<|>)) )
import Control.Monad (forever)
import Control.Concurrent
import System.IO hiding (getContents)
import Control.Exception (SomeException)
import qualified Control.Exception as E

-- | Relp server options
data RelpFlow s =>  RelpServerParams s = RelpServerParams
  { relpServerReport :: !(s -> SockAddr -> String -> String -> IO ())
  , relpServerAccept :: !(s -> SockAddr -> RelpOffers -> IO Bool)
  , relpServerNotify :: !(s -> SockAddr -> ByteString -> IO Bool)
  , relpServerReduce :: !(s -> SockAddr -> IO ())
  , relpServerFinish :: !(s -> SockAddr -> IO ())
  }

-- | Relp server options stub
instance RelpFlow s => Default (RelpServerParams s) where
  def = RelpServerParams
    (\_ a t -> hPutStrLn stderr . ((show a <> " " <> t <> ": ")<>))
    (\_ _ _ -> pure True)
    (\_ _ _ -> pure True)
    (\_ _ -> pure ())
    (\_ _ -> pure ())

data RelpCommand = RelpRSP | RelpOPEN | RelpSYSLOG | RelpCLOSE
  | RelpCommand ByteString
  deriving (Show, Eq)

data RelpMessage = RelpMessage
  { relpTxnr :: !Int
  , relpCommand :: !RelpCommand
  , relpData :: !ByteString
  } deriving (Show, Eq)

type RelpOffers = [(ByteString, ByteString)]

class RelpFlow a where
  relpFlowRecv :: a -> IO B8.ByteString
  relpFlowSend :: a -> B8.ByteString -> IO ()
  relpFlowClose :: a -> IO ()

instance RelpFlow Socket where
  relpFlowRecv = getContents
  relpFlowSend = sendAll
  relpFlowClose = S.close

instance RelpFlow Context where
  relpFlowRecv = fmap B8.fromStrict . recvData
  relpFlowSend = sendData
  relpFlowClose = bye

-- | Provides a simple RELP server.
runRelpServer :: PortNumber -> RelpServerParams Socket -> IO ()
runRelpServer portnum opts = srv where
  srv = runTCPServer Nothing portnum (buildRelpServerHandle opts)
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
              forkFinally (server conn peer) (const (S.gracefulClose conn 5000))

-- | Provides a simple TLS RELP server.
runRelpTLSServer' :: FilePath -> FilePath -> FilePath
              -> (ServerParams -> ServerParams)
              -> ServiceName -> RelpServerParams Context -> IO ()
runRelpTLSServer' fca fcr fky fhp snm cb = lcrd >>= \cr ->
  readCertificateStore fca >>= \ca ->
  runRelpTLSServer (fhp (makeServerParams cr ca)) HostAny snm cb where
    lcrd = credentialLoadX509Chain fcr [fca] fky <&> either (error . show) id

-- | Provides a TLS RELP server
runRelpTLSServer :: ServerParams -> HostPreference
             -> String -> RelpServerParams Context -> IO ()
runRelpTLSServer params hostprefs servicename opts = srv where
  srv = listen hostprefs servicename acp
  acp (sock, _peer) = forever (acceptFork params sock opn)
  opn (ctx, peer) = buildRelpServerHandle opts ctx peer

-- | Build relp messages handler.
buildRelpServerHandle :: RelpFlow s
                      => RelpServerParams s -- ^ Server options
                      -> s -- ^ Some server socket
                      -> SockAddr -- ^ Client address
                      -> IO () -- ^ Never returns
buildRelpServerHandle RelpServerParams{..} = safeRun where
  safeRun s a = E.try (handleMessage s a) >>= check s a

  check s a (Right ()) = relpServerFinish s a
  check s a (Left (e :: SomeException)) =
    relpServerReport s a "ERROR" (show e) >> relpServerFinish s a

  handleMessage s a = do
    status <- relpFlowRecv s >>= processMessage s a
    if status then handleMessage s a else handleClose s a
  
  handleClose s a = relpServerReduce s a >> relpFlowClose s

  processMessage s a = parseLazy_ err process relpParser where
    err e = relpServerReport s a "ERROR" ("parser: " ++ show e) $> False
    process msg@RelpMessage{ relpCommand = RelpOPEN, relpData = txt } = do
      let offers = parse_ (const []) id relpOffersParser txt
      -- NOTE only version 0 supported!
      let versionValid = (Just "0" ==) $ lookup "relp_version" offers
      if versionValid then do
          relpRsp s msg $ "200 OK "
            ++ "relp_version=0\nrelp_software=hsRELP\ncommands="
            ++ maybe "syslog" toString (lookup "commands" offers)
          relpServerAccept s a offers
        else do
          relpServerReport s a "ERROR" ("unsupported version " <> show offers)
          relpNAck s msg "unsupported RELP version" >> return False
    process msg@RelpMessage{ relpCommand = RelpSYSLOG, relpData = txt } = do
      status <- relpServerNotify s a txt
      if status then relpAck s msg else relpNAck s msg "rejected"
      return status
    process msg = do
      relpServerReport s a "ERROR" ("strange message command: " ++ show msg)
      relpNAck s msg "unexpected message command"
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

relpRsp :: RelpFlow s => s -> RelpMessage -> String -> IO ()
relpRsp sock msg reply = relpFlowSend sock mkReply
  -- putStrLn $ prettyHex $ B8.toStrict mkReply
  where
  mkReply = B8.pack $ show (relpTxnr msg) ++ " rsp "
    ++ show (length reply) ++ " " ++ reply ++ "\n"

relpAck :: RelpFlow s => s -> RelpMessage -> IO ()
relpAck sock msg = relpRsp sock msg "200 OK"

relpNAck :: RelpFlow s => s -> RelpMessage -> String -> IO ()
relpNAck sock msg err = relpRsp sock msg $ "500 " ++ err

-- just shortcuts
parse_ :: (String -> c) -> (b -> c) -> Parser b -> ByteString -> c
parse_ err ok p = either err ok . parseOnly p

parseLazy_ :: (String -> c) -> (b -> c) -> Parser b -> B8.ByteString -> c
parseLazy_ err ok p = either err ok . LBP.eitherResult . LBP.parse p

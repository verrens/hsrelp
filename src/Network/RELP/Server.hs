-- | RELP (Reliable Event Logging Protocol) simple server
{-# LANGUAGE OverloadedStrings #-}
module Network.RELP.Server
  (
    -- * Running a standalone RELP server
    RelpMessageHandler
  , runRelpServer
  )
  where

import Prelude hiding (getContents, take)
import Network.Socket hiding (send, recv)
import Network.Socket.ByteString.Lazy
import Control.Concurrent (forkIO)
import Data.Attoparsec.ByteString
import qualified Data.Attoparsec.ByteString.Lazy as LBP
import qualified Data.ByteString.Lazy.Char8 as B8
import qualified Data.ByteString as B
import Data.ByteString (ByteString)
import Data.ByteString.UTF8 (toString)
import Data.Char
import Data.List (lookup)
import Control.Applicative
import Control.Monad
import qualified Control.Exception as E
import Control.Concurrent (forkFinally)

-- | Message handler callback.
type RelpMessageHandler =
  SockAddr -- ^ Client connection address
  -> ByteString -- ^ Log message
  -> IO Bool -- ^ Reject message (reply error RSP) if False



data RelpCommand = RelpRSP | RelpOPEN | RelpSYSLOG | RelpCLOSE
  | RelpCommand ByteString
  deriving (Show, Eq)

data RelpMessage = RelpMessage
  { relpTxnr :: Int
  , relpCommand :: RelpCommand
  , relpData :: ByteString
  } deriving (Show, Eq)

type RelpOffers = [(ByteString, ByteString)]


-- | Provides a simple RELP server.
runRelpServer :: PortNumber -- ^ Port to listen on
  -> RelpMessageHandler -- ^ Message handler
  -> IO () -- ^ Never returns
runRelpServer port cb = runTCPServer Nothing port handleConnection where
  handleConnection sock = do
    accept sock >>= forkIO . handleMessage
    handleConnection sock

  handleMessage s@(sockh, srcAddr) = do
    status <- getContents sockh >>= processMessage s
    if status then handleMessage s
      else close sockh

  processMessage (sock, srcAddr) = parseLazy_ err process relpParser
    where
    err e = putStrLn ("ERROR: parser: " ++ show e) >> return False

    process msg@RelpMessage{ relpCommand = RelpOPEN } = do
      let offers = parse_ (const []) id relpOffersParser $ relpData msg
      -- NOTE only version 0 supported!
      let versionValid = maybe False (== "0") $ lookup "relp_version" offers
      -- TODO FIXME check commands offer?
      if versionValid then do
          relpRsp sock msg $ "200 OK "
            ++ "relp_version=0\nrelp_software=hsRELP\ncommands="
            ++ (maybe "syslog" toString $ lookup "commands" offers)
          return True
        else relpNAck sock msg "unsupported RELP version" >> return False

    process msg@RelpMessage{ relpCommand = RelpSYSLOG } = do
      status <- cb srcAddr (relpData msg)
      if status then relpAck sock msg else relpNAck sock msg "rejected"
      return status

    process msg = do
      putStrLn ("ERROR: strange message command: " ++ show msg)
      relpNAck sock msg "unexpected message command"
      return False

  runTCPServer :: Maybe HostName -> PortNumber -> (Socket -> IO a) -> IO a
  runTCPServer mhost port server = withSocketsDo $ do
      addr <- resolve
      E.bracket (open addr) close loop
    where
      resolve = do
          let hints = defaultHints {
                  addrFlags = [AI_PASSIVE]
                , addrSocketType = Stream
                }
          head <$> getAddrInfo (Just hints) mhost (Just $ show port)
      open addr = E.bracketOnError (openSocket addr) close $ \sock -> do
          setSocketOption sock ReuseAddr 1
          withFdSocket sock setCloseOnExecIfNeeded
          bind sock $ addrAddress addr
          listen sock 1024
          return sock
      loop sock = forever $ E.bracketOnError (accept sock) (close . fst)
          $ \(conn, _peer) -> void $
              forkFinally (server conn) (const $ gracefulClose conn 5000)


relpParser :: Parser RelpMessage
relpParser = do
  txnr <- decimal <* space
  command <- parseCommand <* space
  datalen <- decimal <* space
  content <- take (datalen + 1) -- <* trailer
  return $ RelpMessage txnr command content
  where
  decimal :: Integral a => Parser a
  decimal = B.foldl' step 0 `fmap` takeWhile1 isDecimal where
    step a c = a * 10 + fromIntegral (c - 48)
    isDecimal c = c >= 48 && c <= 57
  space = word8 32
  trailer = word8 10
  parseCommand =
    string "syslog" *> return RelpSYSLOG
    <|> string "close" *> return RelpCLOSE
    <|> string "open" *> return RelpOPEN
    <|> string "rsp" *> return RelpRSP
    <|> RelpCommand <$> takeWhile1 (/= 32)

relpOffersParser :: Parser RelpOffers 
relpOffersParser = many' $ pair <* word8 sep
  where
  sep = 10 -- \n
  der = 61 -- '='
  pair = liftA2 (,)
    (takeWhile1 (\c-> c /= der && c /= sep))
    (word8 der *> takeWhile1 (/= sep) <|> return "")

relpRsp :: Socket -> RelpMessage -> String -> IO ()
relpRsp sock msg reply = sendAll sock mkReply
  -- putStrLn $ prettyHex $ B8.toStrict mkReply
  where
  mkReply = B8.pack $ (show $ relpTxnr msg) ++ " rsp "
    ++ (show $ length reply) ++ " " ++ reply ++ "\n"

relpAck :: Socket -> RelpMessage -> IO ()
relpAck sock msg = relpRsp sock msg "200 OK"

relpNAck :: Socket -> RelpMessage -> String -> IO ()
relpNAck sock msg err = relpRsp sock msg $ "500 " ++ err

-- just shortcuts
parse_ err ok p = either err ok . parseOnly p
parseLazy_ err ok p = either err ok . LBP.eitherResult . LBP.parse p

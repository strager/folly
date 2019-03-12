/*
 * Copyright 2014-present Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <iostream>

#include <folly/io/async/AsyncServerSocket.h>
#include <folly/io/async/AsyncSocket.h>
#include <folly/io/async/EventBase.h>
#include <folly/portability/GTest.h>
#include <folly/io/async/test/AsyncSocketTest.h>

namespace folly {

#ifndef TCP_SAVE_SYN
#define TCP_SAVE_SYN 27
#endif

// @nocommit TODO: Audit all users of AsyncSocket. Does anyone override
// SendMsgParamsCallback::getFlags and unset MSG_NOSIGNAL?
// @nocommit TODO: See if we can expose AsyncSocket::connect's F_SETNOSIGPIPE
// setting
TEST(AsyncSocketTest, writingToLocalSocketWithDisconnectedPeerFailsWithEpipe) {
  EventBase evb;

  NetworkSocket fds[2];
  PCHECK(netops::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

  auto peer0 = AsyncSocket::newSocket(&evb, fds[0]);
  auto peer1 = AsyncSocket::newSocket(&evb, fds[1]);
  peer0->setNoSigPipe(); // @nocommit
  peer1->setNoSigPipe(); // @nocommit

  peer0->closeNow();

  WriteCallback wcb;
  peer1->write(&wcb, "hello", 5);

  evb.loop();

  ASSERT_EQ(wcb.state, STATE_FAILED);
  // @nocommit add a REMOTE_DISCONNECTED (or whatever) type to AsyncSocketException
  EXPECT_EQ(wcb.exception.getErrno(), EPIPE);
}

TEST(AsyncSocketTest, getSockOpt) {
  EventBase evb;
  std::shared_ptr<AsyncSocket> socket = AsyncSocket::newSocket(&evb, 0);

  int val;
  socklen_t len;

  int expectedRc = getsockopt(
      socket->getNetworkSocket().toFd(), SOL_SOCKET, SO_REUSEADDR, &val, &len);
  int actualRc = socket->getSockOpt(SOL_SOCKET, SO_REUSEADDR, &val, &len);

  EXPECT_EQ(expectedRc, actualRc);
}

TEST(AsyncSocketTest, REUSEPORT) {
  EventBase base;
  auto serverSocket = AsyncServerSocket::newSocket(&base);
  serverSocket->bind(0);
  serverSocket->listen(0);
  serverSocket->startAccepting();

  try {
    serverSocket->setReusePortEnabled(true);
  } catch (...) {
    LOG(INFO) << "Reuse port probably not supported";
    return;
  }

  SocketAddress address;
  serverSocket->getAddress(&address);
  int port = address.getPort();

  auto serverSocket2 = AsyncServerSocket::newSocket(&base);
  serverSocket2->setReusePortEnabled(true);
  serverSocket2->bind(port);
  serverSocket2->listen(0);
  serverSocket2->startAccepting();
}

TEST(AsyncSocketTest, v4v6samePort) {
  EventBase base;
  auto serverSocket = AsyncServerSocket::newSocket(&base);
  serverSocket->bind(0);
  auto addrs = serverSocket->getAddresses();
  ASSERT_GT(addrs.size(), 0);
  uint16_t port = addrs[0].getPort();
  for (const auto& addr : addrs) {
    EXPECT_EQ(port, addr.getPort());
  }
}

TEST(AsyncSocketTest, duplicateBind) {
  EventBase base;
  auto server1 = AsyncServerSocket::newSocket(&base);
  server1->bind(0);
  server1->listen(10);

  SocketAddress address;
  server1->getAddress(std::addressof(address));

  auto server2 = AsyncServerSocket::newSocket(&base);
  EXPECT_THROW(server2->bind(address.getPort()), std::exception);
}

TEST(AsyncSocketTest, tosReflect) {
  EventBase base;
  auto server1 = AsyncServerSocket::newSocket(&base);
  server1->bind(0);
  server1->listen(10);
  int fd = server1->getSocket();

  // Verify if tos reflect is disabled by default
  // and the TCP_SAVE_SYN setting is not enabled
  EXPECT_FALSE(server1->getTosReflect());
  int value;
  socklen_t valueLength = sizeof(value);
  int rc = getsockopt(fd, IPPROTO_TCP, TCP_SAVE_SYN, &value, &valueLength);
  ASSERT_EQ(rc, 0);
  ASSERT_EQ(value, 0);

  // Enable TOS reflect on the server socket
  server1->setTosReflect(true);

  // Verify if tos reflect is enabled now
  // and the TCP_SAVE_SYN setting is also enabled
  EXPECT_TRUE(server1->getTosReflect());
  rc = getsockopt(fd, IPPROTO_TCP, TCP_SAVE_SYN, &value, &valueLength);
  ASSERT_EQ(rc, 0);
  ASSERT_EQ(value, 1);
}

} // namespace folly

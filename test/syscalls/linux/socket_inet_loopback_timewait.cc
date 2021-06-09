// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"

namespace gvisor {
namespace testing {

namespace {

using SocketInetLoopbackTest = ::testing::TestWithParam<SocketInetTestParam>;

TEST_P(SocketInetLoopbackTest, TCPActiveCloseTimeWaitTest) {
  auto const& param = GetParam();
  sockaddr_storage listen_addr, conn_bound_addr;
  listen_addr = param.listener.addr;
  SetupTimeWaitClose(&param.listener, &param.connector, false /*reuse*/,
                     false /*accept_close*/, &listen_addr, &conn_bound_addr);
  FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(param.connector.family(), SOCK_STREAM, IPPROTO_TCP));

  ASSERT_THAT(bind(conn_fd.get(), AsSockAddr(&conn_bound_addr),
                   param.connector.addr_len),
              SyscallFailsWithErrno(EADDRINUSE));
}

TEST_P(SocketInetLoopbackTest, TCPActiveCloseTimeWaitReuseTest) {
  auto const& param = GetParam();
  sockaddr_storage listen_addr, conn_bound_addr;
  listen_addr = param.listener.addr;
  SetupTimeWaitClose(&param.listener, &param.connector, true /*reuse*/,
                     false /*accept_close*/, &listen_addr, &conn_bound_addr);
  FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(param.connector.family(), SOCK_STREAM, IPPROTO_TCP));
  ASSERT_THAT(setsockopt(conn_fd.get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(conn_fd.get(), AsSockAddr(&conn_bound_addr),
                   param.connector.addr_len),
              SyscallFailsWithErrno(EADDRINUSE));
}

// These tests are disabled under random save as the restore run
// results in the stack.Seed() being different which can cause
// sequence number of final connect to be one that is considered
// old and can cause the test to be flaky.
//
// Test re-binding of client and server bound addresses when the older
// connection is in TIME_WAIT.
TEST_P(SocketInetLoopbackTest, TCPPassiveCloseNoTimeWaitTest) {
  auto const& param = GetParam();
  sockaddr_storage listen_addr, conn_bound_addr;
  listen_addr = param.listener.addr;
  SetupTimeWaitClose(&param.listener, &param.connector, false /*reuse*/,
                     true /*accept_close*/, &listen_addr, &conn_bound_addr);

  // Now bind a new socket and verify that we can immediately rebind the address
  // bound by the conn_fd as it never entered TIME_WAIT.
  const FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(param.connector.family(), SOCK_STREAM, IPPROTO_TCP));
  ASSERT_THAT(bind(conn_fd.get(), AsSockAddr(&conn_bound_addr),
                   param.connector.addr_len),
              SyscallSucceeds());

  FileDescriptor listen_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(param.listener.family(), SOCK_STREAM, IPPROTO_TCP));
  ASSERT_THAT(
      bind(listen_fd.get(), AsSockAddr(&listen_addr), param.listener.addr_len),
      SyscallFailsWithErrno(EADDRINUSE));
}

TEST_P(SocketInetLoopbackTest, TCPPassiveCloseNoTimeWaitReuseTest) {
  auto const& param = GetParam();
  sockaddr_storage listen_addr, conn_bound_addr;
  listen_addr = param.listener.addr;
  SetupTimeWaitClose(&param.listener, &param.connector, true /*reuse*/,
                     true /*accept_close*/, &listen_addr, &conn_bound_addr);

  FileDescriptor listen_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(param.listener.family(), SOCK_STREAM, IPPROTO_TCP));
  ASSERT_THAT(setsockopt(listen_fd.get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(
      bind(listen_fd.get(), AsSockAddr(&listen_addr), param.listener.addr_len),
      SyscallSucceeds());
  ASSERT_THAT(listen(listen_fd.get(), SOMAXCONN), SyscallSucceeds());

  // Now bind and connect  new socket and verify that we can immediately rebind
  // the address bound by the conn_fd as it never entered TIME_WAIT.
  const FileDescriptor conn_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(param.connector.family(), SOCK_STREAM, IPPROTO_TCP));
  ASSERT_THAT(setsockopt(conn_fd.get(), SOL_SOCKET, SO_REUSEADDR, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
  ASSERT_THAT(bind(conn_fd.get(), AsSockAddr(&conn_bound_addr),
                   param.connector.addr_len),
              SyscallSucceeds());

  uint16_t const port =
      ASSERT_NO_ERRNO_AND_VALUE(AddrPort(param.listener.family(), listen_addr));
  sockaddr_storage conn_addr = param.connector.addr;
  ASSERT_NO_ERRNO(SetAddrPort(param.connector.family(), &conn_addr, port));
  ASSERT_THAT(RetryEINTR(connect)(conn_fd.get(), AsSockAddr(&conn_addr),
                                  param.connector.addr_len),
              SyscallSucceeds());
}

INSTANTIATE_TEST_SUITE_P(All, SocketInetLoopbackTest,
                         SocketInetLoopbackTestValues(),
                         DescribeSocketInetTestParam);

}  // namespace

}  // namespace testing
}  // namespace gvisor

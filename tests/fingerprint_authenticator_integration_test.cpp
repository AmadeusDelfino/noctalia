#include "auth/fingerprint_authenticator.h"
#include "core/timer_manager.h"
#include "dbus/system_bus.h"
#include "i18n/i18n.h"
#include "tests/test_check.h"

#include <algorithm>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <print>
#include <sdbus-c++/sdbus-c++.h>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

  const sdbus::ServiceName kFprintBusName{"net.reactivated.Fprint"};
  const sdbus::ObjectPath kManagerPath{"/net/reactivated/Fprint/Manager"};
  const sdbus::ObjectPath kDevicePath{"/net/reactivated/Fprint/Device/0"};
  constexpr auto kManagerInterface = "net.reactivated.Fprint.Manager";
  constexpr auto kDeviceInterface = "net.reactivated.Fprint.Device";

  // Mirrors fprintd's claim rules (_fprint_device_check_claimed in fprintd's device.c): one session per
  // device, Claim fails while any session exists, and only the claiming sender may use or release it.
  class FakeFprintd {
  public:
    struct Call {
      std::string method;
      std::string sender;
      bool accepted = false;
    };

    FakeFprintd()
        : m_connection(sdbus::createSessionBusConnection(kFprintBusName)),
          m_manager(sdbus::createObject(*m_connection, kManagerPath)) {
      m_manager->addVTable(
                   sdbus::registerMethod("GetDefaultDevice").implementedAs([] { return kDevicePath; })
      ).forInterface(kManagerInterface);
      m_device = sdbus::createObject(*m_connection, kDevicePath);
      m_device
          ->addVTable(
              sdbus::registerMethod("Claim")
                  .withInputParamNames("username")
                  .implementedAs([this](const std::string& /*username*/) { claim(currentSender()); }),
              sdbus::registerMethod("Release").implementedAs([this] { requireOwner("Release", true); }),
              sdbus::registerMethod("VerifyStart")
                  .withInputParamNames("finger_name")
                  .implementedAs([this](const std::string& /*fingerName*/) { requireOwner("VerifyStart", false); }),
              sdbus::registerMethod("VerifyStop").implementedAs([this] { requireOwner("VerifyStop", false); }),
              sdbus::registerSignal("VerifyStatus").withParameters<std::string, bool>("result", "done")
          )
          .forInterface(kDeviceInterface);
      m_connection->enterEventLoopAsync();
    }

    ~FakeFprintd() { m_connection->leaveEventLoop(); }

    FakeFprintd(const FakeFprintd&) = delete;
    FakeFprintd& operator=(const FakeFprintd&) = delete;

    void emitVerifyStatus(const std::string& result, bool done) {
      m_device->emitSignal("VerifyStatus").onInterface(kDeviceInterface).withArguments(result, done);
    }

    // fprintd unexports the device object when the reader is unplugged.
    void removeDevice() { m_device->unregister(); }

    // fprintd exits or crashes: the name has no owner and nothing activates it on the test bus.
    void dropBusName() { m_connection->releaseName(kFprintBusName); }

    std::string owner() const {
      std::scoped_lock lock(m_mutex);
      return m_claimOwner;
    }

    long calls(const std::string& method, const std::string& sender) const {
      std::scoped_lock lock(m_mutex);
      return std::ranges::count_if(m_log, [&](const Call& c) { return c.method == method && c.sender == sender; });
    }

    long accepted(const std::string& method, const std::string& sender) const {
      std::scoped_lock lock(m_mutex);
      return std::ranges::count_if(m_log, [&](const Call& c) {
        return c.method == method && c.sender == sender && c.accepted;
      });
    }

    std::vector<std::string> acceptedMethods(const std::string& sender) const {
      std::scoped_lock lock(m_mutex);
      std::vector<std::string> out;
      for (const auto& c : m_log) {
        if (c.sender == sender && c.accepted) {
          out.push_back(c.method);
        }
      }
      return out;
    }

  private:
    std::string currentSender() const { return m_device->getCurrentlyProcessedMessage().getSender(); }

    void claim(const std::string& sender) {
      {
        std::scoped_lock lock(m_mutex);
        const bool free = m_claimOwner.empty();
        m_log.push_back({"Claim", sender, free});
        if (free) {
          m_claimOwner = sender;
          return;
        }
      }
      throw sdbus::Error(sdbus::Error::Name{"net.reactivated.Fprint.Error.AlreadyInUse"}, "Device was already claimed");
    }

    void requireOwner(const std::string& method, bool release) {
      sdbus::Error::Name errorName;
      std::string errorMessage;
      const std::string sender = currentSender();
      {
        std::scoped_lock lock(m_mutex);
        if (m_claimOwner.empty()) {
          errorName = sdbus::Error::Name{"net.reactivated.Fprint.Error.ClaimDevice"};
          errorMessage = "Device was not claimed before use";
        } else if (m_claimOwner != sender) {
          errorName = sdbus::Error::Name{"net.reactivated.Fprint.Error.AlreadyInUse"};
          errorMessage = "Device already in use by another user";
        }
        m_log.push_back({method, sender, errorName.empty()});
        if (errorName.empty()) {
          if (release) {
            m_claimOwner.clear();
          }
          return;
        }
      }
      throw sdbus::Error(std::move(errorName), std::move(errorMessage));
    }

    std::unique_ptr<sdbus::IConnection> m_connection;
    std::unique_ptr<sdbus::IObject> m_manager;
    std::unique_ptr<sdbus::IObject> m_device;
    mutable std::mutex m_mutex;
    std::string m_claimOwner;
    std::vector<Call> m_log;
  };

  void pump(SystemBus& bus) {
    bus.processPendingEvents();
    TimerManager::instance().tick();
  }

  template <typename Predicate> void drainUntil(SystemBus& bus, Predicate&& predicate) {
    for (int attempt = 0; attempt < 2000; ++attempt) {
      pump(bus);
      if (std::invoke(predicate)) {
        return;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    noctalia::test::failCheck("timed out waiting for D-Bus state");
  }

  // Lets any stray follow-up calls (re-arms, retries) reach the fake before asserting on counts.
  void settle(SystemBus& bus) {
    for (int i = 0; i < 100; ++i) {
      pump(bus);
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }

  void armAndWaitForVerify(FingerprintAuthenticator& auth, SystemBus& bus, FakeFprintd& fake, const std::string& self) {
    const long before = fake.accepted("VerifyStart", self);
    auth.start();
    drainUntil(bus, [&] { return fake.accepted("VerifyStart", self) == before + 1; });
    TEST_CHECK(fake.owner() == self);
  }

  class AttemptFixture {
  public:
    AttemptFixture() {
      m_auth.setStatusCallback([this](const std::string& message, bool error) {
        m_statuses.emplace_back(message, error);
      });
    }

    void start() {
      m_auth.start();
      // The device discovery prompt is synchronous. The next ready status acknowledges VerifyStart.
      waitForReady();
      TEST_CHECK(m_fake.owner() == m_self);
    }

    void stop() {
      m_auth.stop();
      TEST_CHECK(m_fake.owner().empty());
    }

    void startWithoutWaiting() { m_auth.start(); }

    void resetAttempts() { m_auth.resetAttempts(); }

    void match() {
      bool authenticated = false;
      m_auth.setAuthenticatedCallback([&authenticated] { authenticated = true; });
      m_fake.emitVerifyStatus("verify-match", true);
      drainUntil(m_bus, [&] { return authenticated; });
      m_auth.setAuthenticatedCallback({});
    }

    long requests() const { return m_fake.calls("VerifyStart", m_self); }

    void waitForReady() { expectNextStatus(m_statuses.size(), "auth.fingerprint.ready", false); }

    void mismatch(std::string_view expected) { verifyStatus("verify-no-match", true, expected, true); }

    void verifyStatus(const std::string& result, bool done, std::string_view key, bool error) {
      expectStatus(sendStatus(result, done), key, error);
    }

    void exhaust() {
      // Establish a depleted budget independently of the exact limit test.
      for (int attempt = 0; attempt < 4; ++attempt) {
        const auto status = sendStatus("verify-no-match", true);
        if (status == std::pair(i18n::tr("auth.fingerprint.too-many-attempts"), true)) {
          return;
        }
        expectStatus(status, "auth.fingerprint.no-match", true);
        waitForReady();
      }
      noctalia::test::failCheck("fingerprint budget was not exhausted");
    }

    std::pair<std::string, bool> sendStatus(const std::string& result, bool done) {
      const auto before = m_statuses.size();
      m_fake.emitVerifyStatus(result, done);
      return nextStatus(before);
    }

    void expectNoNewRequests(long expected) {
      const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(400);
      do {
        pump(m_bus);
        expectRequests(expected);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      } while (std::chrono::steady_clock::now() < deadline);
      pump(m_bus);
      expectRequests(expected);
    }

  private:
    void expectRequests(long expected) const {
      const auto observed = requests();
      if (observed != expected) {
        std::println(stderr, "VerifyStart requests: got {}, expected {}", observed, expected);
        TEST_CHECK(observed == expected);
      }
    }

    static void expectStatus(const std::pair<std::string, bool>& status, std::string_view key, bool error) {
      const auto expected = i18n::tr(key);
      if (status != std::pair(expected, error)) {
        std::println(
            stderr, "Fingerprint status: got '{}' (error={}), expected '{}' (error={})", status.first, status.second,
            expected, error
        );
        TEST_CHECK(status == std::pair(expected, error));
      }
    }

    std::pair<std::string, bool> nextStatus(std::size_t before) {
      drainUntil(m_bus, [&] { return m_statuses.size() > before; });
      return m_statuses[before];
    }

    void expectNextStatus(std::size_t before, std::string_view key, bool error) {
      expectStatus(nextStatus(before), key, error);
    }

    FakeFprintd m_fake;
    SystemBus m_bus;
    const std::string m_self = m_bus.connection().getUniqueName();
    std::vector<std::pair<std::string, bool>> m_statuses;
    FingerprintAuthenticator m_auth{m_bus};
  };

  void thirdMismatchExhaustsAttempts() {
    AttemptFixture fixture;
    fixture.start();
    fixture.mismatch("auth.fingerprint.no-match");
    fixture.waitForReady();
    fixture.mismatch("auth.fingerprint.no-match");
    fixture.waitForReady();
    fixture.mismatch("auth.fingerprint.too-many-attempts");
    fixture.expectNoNewRequests(3);
  }

  void stoppedReadingDoesNotRestoreOrConsumeAttempts() {
    AttemptFixture fixture;
    fixture.start();
    fixture.mismatch("auth.fingerprint.no-match");
    fixture.waitForReady();
    fixture.mismatch("auth.fingerprint.no-match");
    fixture.waitForReady();
    fixture.stop(); // Cancel an armed reading without receiving a result.
    fixture.start();
    fixture.mismatch("auth.fingerprint.too-many-attempts");
    fixture.expectNoNewRequests(4);
  }

  void exhaustedAuthenticatorDoesNotRestart() {
    AttemptFixture fixture;
    fixture.start();
    fixture.exhaust();
    const auto before = fixture.requests();
    fixture.stop();
    fixture.startWithoutWaiting();
    fixture.expectNoNewRequests(before);
  }

  void newLockRestoresAttemptsOnSameAuthenticator() {
    AttemptFixture fixture;
    fixture.start();
    fixture.exhaust();
    fixture.stop();          // The screen releases the device when unlocking.
    fixture.resetAttempts(); // The next confirmed lock resets the same authenticator.
    fixture.start();
    fixture.match();
    fixture.stop();
  }

  void technicalErrorAndScanGuidanceDoNotConsumeMismatchAttempts() {
    AttemptFixture fixture;
    fixture.start();
    fixture.verifyStatus("verify-unknown-error", true, "auth.fingerprint.error", true);
    fixture.waitForReady();
    fixture.verifyStatus("verify-retry-scan", false, "auth.fingerprint.retry", false);
    fixture.mismatch("auth.fingerprint.no-match");
    fixture.waitForReady();
    fixture.mismatch("auth.fingerprint.no-match");
    fixture.waitForReady();
    fixture.mismatch("auth.fingerprint.too-many-attempts");
    fixture.expectNoNewRequests(4);
  }

  void disconnectedVerifyReleasesClaimOnStop() {
    FakeFprintd fake;
    SystemBus bus;
    FingerprintAuthenticator auth(bus);
    const std::string self = bus.connection().getUniqueName();

    armAndWaitForVerify(auth, bus, fake, self);

    // libfprint reports TOO_HOT (and PROTO/REMOVED) as verify-disconnected; fprintd keeps the claim.
    fake.emitVerifyStatus("verify-disconnected", true);
    drainUntil(bus, [&] { return fake.calls("VerifyStop", self) == 1; });
    settle(bus);
    TEST_CHECK(fake.calls("VerifyStart", self) == 1); // a disconnect still does not re-arm verification
    TEST_CHECK(fake.owner() == self);                 // the claim is held until cleanup, as before

    auth.stop();
    TEST_CHECK(fake.accepted("Release", self) == 1);
    TEST_CHECK(fake.owner().empty());

    // The next attempt from the same long-lived connection must be able to claim again (#4591).
    armAndWaitForVerify(auth, bus, fake, self);
    TEST_CHECK(fake.calls("Claim", self) == 2);
    TEST_CHECK(fake.accepted("Claim", self) == 2);

    auth.stop();
    TEST_CHECK(fake.owner().empty());
  }

  void matchedVerifyReleasesClaimOnStop() {
    FakeFprintd fake;
    SystemBus bus;
    FingerprintAuthenticator auth(bus);
    const std::string self = bus.connection().getUniqueName();
    int authenticated = 0;
    auth.setAuthenticatedCallback([&authenticated] { ++authenticated; });

    armAndWaitForVerify(auth, bus, fake, self);
    fake.emitVerifyStatus("verify-match", true);
    drainUntil(bus, [&] { return authenticated == 1; });

    auth.stop();
    TEST_CHECK(fake.owner().empty());
    const std::vector<std::string> expected{"Claim", "VerifyStart", "VerifyStop", "Release"};
    TEST_CHECK(fake.acceptedMethods(self) == expected);
  }

  void foreignClaimIsLeftAlone() {
    FakeFprintd fake;
    auto foreign = sdbus::createSessionBusConnection();
    auto foreignDevice = sdbus::createProxy(*foreign, kFprintBusName, kDevicePath);
    foreignDevice->callMethod("Claim").onInterface(kDeviceInterface).withArguments(std::string{});
    const std::string foreignName = foreign->getUniqueName();
    TEST_CHECK(fake.owner() == foreignName);

    SystemBus bus;
    FingerprintAuthenticator auth(bus);
    const std::string self = bus.connection().getUniqueName();

    auth.start();
    drainUntil(bus, [&] { return fake.calls("Claim", self) == 1; });
    settle(bus);
    TEST_CHECK(fake.accepted("Claim", self) == 0);
    TEST_CHECK(fake.calls("VerifyStart", self) == 0);

    auth.stop();
    settle(bus);
    TEST_CHECK(fake.owner() == foreignName);
    TEST_CHECK(fake.accepted("Release", self) == 0);
    TEST_CHECK(fake.calls("Claim", self) == 1); // no reclaim loop
  }

  void stopAfterDeviceRemovalIsBounded() {
    FakeFprintd fake;
    SystemBus bus;
    FingerprintAuthenticator auth(bus);
    const std::string self = bus.connection().getUniqueName();

    armAndWaitForVerify(auth, bus, fake, self);
    fake.emitVerifyStatus("verify-disconnected", true);
    drainUntil(bus, [&] { return fake.calls("VerifyStop", self) == 1; });
    fake.removeDevice();

    const auto begin = std::chrono::steady_clock::now();
    auth.stop();
    TEST_CHECK(std::chrono::steady_clock::now() - begin < std::chrono::seconds(2));
    TEST_CHECK(fake.calls("Release", self) == 0); // the unexported object never sees the call
  }

  void stopAfterServiceExitIsBounded() {
    FakeFprintd fake;
    SystemBus bus;
    FingerprintAuthenticator auth(bus);
    const std::string self = bus.connection().getUniqueName();

    armAndWaitForVerify(auth, bus, fake, self);
    fake.emitVerifyStatus("verify-disconnected", true);
    drainUntil(bus, [&] { return fake.calls("VerifyStop", self) == 1; });
    fake.dropBusName();

    const auto begin = std::chrono::steady_clock::now();
    auth.stop();
    TEST_CHECK(std::chrono::steady_clock::now() - begin < std::chrono::seconds(2));
  }

} // namespace

int main() {
  disconnectedVerifyReleasesClaimOnStop();
  matchedVerifyReleasesClaimOnStop();
  foreignClaimIsLeftAlone();
  stopAfterDeviceRemovalIsBounded();
  stopAfterServiceExitIsBounded();
  thirdMismatchExhaustsAttempts();
  stoppedReadingDoesNotRestoreOrConsumeAttempts();
  exhaustedAuthenticatorDoesNotRestart();
  newLockRestoresAttemptsOnSameAuthenticator();
  technicalErrorAndScanGuidanceDoNotConsumeMismatchAttempts();
  return 0;
}

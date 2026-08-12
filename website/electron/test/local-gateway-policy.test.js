const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { decideLocalSpawn } = require("../local-gateway-policy");

describe("decideLocalSpawn", () => {
  // Default-on: a fresh store (or one predating the key) must behave exactly
  // as before the setting existed — spawn a local gateway.
  it("spawns by default (setting unset)", () => {
    assert.deepEqual(
      decideLocalSpawn({ runLocalGateway: undefined, remoteHost: "" }),
      { spawn: true, reason: "local-gateway-enabled" },
    );
  });

  it("spawns when the setting is on, even with a remote configured", () => {
    // A configured remote host alone must not suppress the spawn — that would
    // change behavior for every tunnel user who never touched the setting.
    assert.deepEqual(
      decideLocalSpawn({ runLocalGateway: true, remoteHost: "dev.example.com" }),
      { spawn: true, reason: "local-gateway-enabled" },
    );
  });

  // The one combination that declines: explicit opt-out AND a configured
  // remote to prefer. The host is carried so the caller can name it in the
  // unreachable-state dialog.
  it("does not spawn when off with a remote configured", () => {
    assert.deepEqual(
      decideLocalSpawn({ runLocalGateway: false, remoteHost: "dev.example.com" }),
      { spawn: false, reason: "remote-preferred", host: "dev.example.com" },
    );
  });

  // Setting off but no remote configured: spawn anyway. Refusing to start
  // anything when there is nowhere else to connect would brick the launch —
  // the setting means "prefer my configured remote", not "never run a gateway".
  it("spawns when off but no remote is configured", () => {
    assert.deepEqual(
      decideLocalSpawn({ runLocalGateway: false, remoteHost: "" }),
      { spawn: true, reason: "no-remote-configured" },
    );
    assert.deepEqual(
      decideLocalSpawn({ runLocalGateway: false, remoteHost: undefined }),
      { spawn: true, reason: "no-remote-configured" },
    );
  });

  // Only the literal `false` (what the IPC setter writes) disables the spawn.
  // A corrupted or hand-edited store value must degrade to today's behavior,
  // never to "no gateway at all".
  it("treats anything but literal false as enabled", () => {
    for (const v of ["false", 0, null, "", {}]) {
      assert.equal(
        decideLocalSpawn({ runLocalGateway: v, remoteHost: "dev.example.com" }).spawn,
        true,
        `value ${JSON.stringify(v)} must not disable the spawn`,
      );
    }
  });

  // Next-launch scoping, the recovery half: a gateway THIS session spawned
  // keeps its recovery respawns even after the user flips the setting off
  // mid-session with a remote configured. Without this, an owned gateway that
  // exits or wedges after the flip would never be respawned, stranding the
  // running session despite the UI promising "takes effect on next launch".
  it("recovery of an owned gateway overrides the off setting", () => {
    assert.deepEqual(
      decideLocalSpawn({
        runLocalGateway: false,
        remoteHost: "dev.example.com",
        ownedGatewayActive: true,
      }),
      { spawn: true, reason: "recovering-owned-gateway" },
    );
  });

  // The override is ownership-scoped: with no owned gateway (every fresh
  // boot, and every reuse/tunnel session) the persisted setting governs.
  it("no ownership means the persisted setting governs", () => {
    assert.equal(
      decideLocalSpawn({
        runLocalGateway: false,
        remoteHost: "dev.example.com",
        ownedGatewayActive: false,
      }).spawn,
      false,
    );
  });
});

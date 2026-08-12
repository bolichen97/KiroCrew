"use strict";
//
// Pure decision logic for the "Run Local Gateway" setting (Settings →
// Developer), extracted from main.js so it can be unit-tested without Electron
// (mirrors gateway-recovery.js). main.js binds the real store value and the
// per-port remote-host config to this function.
//
// The setting expresses INTENT — "this machine is a pure client of my remote
// gateway" — which is a different question from the health-probe outcome that
// startGateway() otherwise decides on. A configured remote host alone must not
// suppress the spawn (that would change behavior for every tunnel user), and a
// failed probe alone must not suppress it either (that is the normal cold-boot
// path). Only the explicit opt-out, paired with a configured remote to prefer,
// declines to spawn.

/**
 * Decide whether the desktop shell may spawn a local gateway on its primary
 * port. Called only after the health probe found nothing usable to reuse —
 * reuse and abort outcomes never reach this decision.
 *
 * @param {object} o
 * @param {*} o.runLocalGateway  the persisted setting. Only the literal
 *   `false` (the value the IPC setter writes) disables the spawn: the default
 *   is spawn-on, and a corrupted or legacy store value must degrade to
 *   today's behavior, never to "no gateway at all".
 * @param {string} [o.remoteHost]  the configured remote host for this port
 *   (`remoteHosts[PORT].host`), or "" when none is configured.
 * @param {boolean} [o.ownedGatewayActive]  true when THIS session already
 *   spawned a local gateway (main.js's `weSpawnedGateway`). The setting is
 *   next-launch scoped, so a mid-session flip to off must not strand the
 *   running session: recovery respawns of a gateway this app owns stay
 *   allowed, and the persisted `false` gates only a future launch. Always
 *   false on a fresh boot, so launch semantics are untouched.
 * @returns {{spawn: true, reason: "local-gateway-enabled"|"no-remote-configured"|"recovering-owned-gateway"}
 *          |{spawn: false, reason: "remote-preferred", host: string}}
 */
function decideLocalSpawn({ runLocalGateway, remoteHost, ownedGatewayActive = false }) {
  if (ownedGatewayActive) {
    return { spawn: true, reason: "recovering-owned-gateway" };
  }
  if (runLocalGateway !== false) {
    return { spawn: true, reason: "local-gateway-enabled" };
  }
  if (!remoteHost) {
    // Setting off but nowhere else to connect: spawn anyway. The setting is
    // about PREFERRING a configured remote; refusing to start anything when
    // no remote exists would leave the app with no gateway at all — a bricked
    // launch a user can only escape by editing the store file by hand.
    return { spawn: true, reason: "no-remote-configured" };
  }
  return { spawn: false, reason: "remote-preferred", host: String(remoteHost) };
}

module.exports = { decideLocalSpawn };

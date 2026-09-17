/**
 * このオーケストレータープロセスがどちらの立場で動くかを決める。
 *
 *   ORCHESTRATOR_VARIANT=trusted   (既定) : Client registry に登録が許可されている
 *   ORCHESTRATOR_VARIANT=untrusted        : 登録が許可されていない
 *
 * コードは全く同じで、違うのは名乗る client_id (= CIMD の URL) と待ち受けポートだけ。
 * 「同じ実装でも、registry に登録されていなければ認可されない」ことを確かめるための仕組み。
 */
import {
  ORCHESTRATORS,
  type OrchestratorProfile,
  type OrchestratorVariant,
} from '../shared/config.js';

const requested = process.env.ORCHESTRATOR_VARIANT;
const variant: OrchestratorVariant = requested === 'untrusted' ? 'untrusted' : 'trusted';

export const PROFILE: OrchestratorProfile = ORCHESTRATORS[variant];
export const IS_UNTRUSTED = variant === 'untrusted';

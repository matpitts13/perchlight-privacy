// A per-invocation budget of outbound requests and binding calls.
// Copied from perchlight-hooks src/lib/budget.js (from perchlight-forms
// src/lib/budget.js); the costs are this Worker's. One budget per Scanner
// invocation: every fetch reserves its worst case before it starts and gives
// back what it didn't use; work that doesn't fit waits for the next chunk.
//
// Workers Free allows 50 subrequests per invocation. Whether D1 and
// send_email binding calls count toward the 50 isn't confirmed (docs/SDD.md,
// "Couldn't verify"), so this assumes they do and keeps an invocation at 45.

export const SUBREQUEST_BUDGET = 45;

/** Worst cases, counted by hand from the code. */
export const COST = {
  // a followed redirect is one more fetch each; at most 5 hops
  maxHops: 5,
  // A and AAAA lookups for a host not yet checked this scan
  dns: 2,
  // one page: the fetch, up to 5 redirects, DNS for one new host on the way
  page: 1 + 5 + 2,
  // kept back in every invocation for D1 (a read, a write, a delivery sync) and one alert
  reserve: 4,
};

export function newBudget(total = SUBREQUEST_BUDGET) {
  return { left: total, used: 0 };
}

export function left(budget) {
  return budget ? budget.left : Infinity;
}

/** Takes n from the budget if it's there. */
export function spend(budget, n = 1) {
  if (!budget) return true;
  if (budget.left < n) return false;
  budget.left -= n;
  budget.used += n;
  return true;
}

/** Gives back what a reservation didn't use. */
export function refund(budget, n) {
  if (!budget || n <= 0) return;
  budget.left += n;
  budget.used -= n;
}

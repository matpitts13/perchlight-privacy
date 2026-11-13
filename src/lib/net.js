// The network, in one place so tests can replace it.
export const net = {
  fetch: (input, init) => fetch(input, init),
};

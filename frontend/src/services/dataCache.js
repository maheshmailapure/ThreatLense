// In-memory frontend cache to ensure instant (0ms) page navigation between dashboards
const store = {};

export const getCachedData = (key, fallback = null) => {
  return store[key] !== undefined ? store[key] : fallback;
};

export const setCachedData = (key, data) => {
  store[key] = data;
};

export const hasCachedData = (key) => {
  return store[key] !== undefined && store[key] !== null;
};

export const getTimestampDiffInMs = (timestampMs: number): number => {
  const nowTimestampMs = new Date().getTime();
  return nowTimestampMs - timestampMs;
};

export const convertMsToMinutes = (ms: number): number => {
  return ms / 1000 / 60;
};

export default { getTimestampDiffInMs, convertMsToMinutes };

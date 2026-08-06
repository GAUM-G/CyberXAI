const IST_OFFSET_MINUTES = 330;
const IST_OFFSET_MILLISECONDS = IST_OFFSET_MINUTES * 60 * 1000;

function toISTISOString(value = new Date()) {
  const instant = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(instant.getTime())) {
    throw new TypeError("A valid date is required");
  }
  return new Date(instant.getTime() + IST_OFFSET_MILLISECONDS)
    .toISOString()
    .replace("Z", "+05:30");
}

module.exports = {
  IST_OFFSET_MINUTES,
  toISTISOString,
};

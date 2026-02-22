function log(level, message, context = {}) {
  const entry = {
    level,
    message,
    context,
    time: new Date().toISOString(),
  };
  const serialized = JSON.stringify(entry);
  if (level === 'error') {
    console.error(serialized);
  } else {
    console.log(serialized);
  }
}

module.exports = {
  info: (message, context) => log('info', message, context),
  warn: (message, context) => log('warn', message, context),
  error: (message, context) => log('error', message, context),
};

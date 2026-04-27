const env = process.env.NODE_ENV || 'development';

const logger = {
  info(message, meta) {
    if (env !== 'test') process.stdout.write(`${message}${meta ? ` ${JSON.stringify(meta)}` : ''}\n`);
  },
  error(message, error) {
    if (env !== 'test') {
      const detail = error && error.message ? error.message : error;
      process.stderr.write(`${message}${detail ? `: ${detail}` : ''}\n`);
    }
  }
};

module.exports = { logger };

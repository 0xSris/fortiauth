const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { validators } = require('../utils/validators');
const { rejectInvalid } = require('../middleware/sanitize');
const { askGroq } = require('../services/aiService');

const router = express.Router();
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

router.use(requireAuth);

router.post('/ask', validators.aiAsk, rejectInvalid, asyncHandler(async (req, res) => {
  try {
    const result = await askGroq({ userId: req.user.userId, question: req.body.question });
    return res.json(result);
  } catch (error) {
    if (error.code === 'GROQ_NOT_CONFIGURED') {
      return res.status(503).json({ error: 'Groq API key is not configured on the server', code: 'GROQ_NOT_CONFIGURED' });
    }
    if (error.name === 'AbortError') {
      return res.status(504).json({ error: 'AI request timed out', code: 'AI_TIMEOUT' });
    }
    return res.status(error.status || 502).json({
      error: process.env.NODE_ENV === 'production' ? 'AI assistant request failed' : `AI assistant request failed: ${error.message}`,
      code: error.code || 'AI_REQUEST_FAILED'
    });
  }
}));

module.exports = router;

/* eslint-disable import/no-extraneous-dependencies */
const validateBodyMaxLengthIgnoringDeps = async (parsedCommit) => {
  const { maxLineLength } = await import('@commitlint/ensure');

  const { type, scope, body } = parsedCommit
  const isDepsCommit =
      type === 'chore'
      && body != null
      && body.includes('Updates the requirements on');

  const bodyMaxLineLength = 1000;

  return [
    isDepsCommit || !body || maxLineLength(body, bodyMaxLineLength),
    `body's lines must not be longer than ${bodyMaxLineLength}`,
  ]
}

export default {
  extends: ['@commitlint/config-conventional'],
  plugins: ['commitlint-plugin-function-rules'],
  rules: {
    'body-max-line-length': [0],
    'function-rules/body-max-line-length': [
      2,
      'always',
      validateBodyMaxLengthIgnoringDeps,
    ],
  },
}

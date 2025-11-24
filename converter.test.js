const { parseTrojan } = require('./converter');

describe('parseTrojan', () => {
  it('should correctly decode a percent-encoded password', () => {
    const link = 'trojan://p%40ss%23word@example.com:443#MyTrojan';
    const result = parseTrojan(link);
    expect(result.password).toBe('p@ss#word');
  });
});
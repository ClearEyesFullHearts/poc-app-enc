// CommonJS because OpenApiValidator do not handle ES Modules
module.exports = {
  createUser: (req, res, next) => {
    import('./actions/users.js').then(({ createUser }) => {
      createUser(req, res, next);
    });
  },
  logUser: (req, res, next) => {
    import('./actions/users.js').then(({ logUser }) => {
      logUser(req, res, next);
    });
  },
};

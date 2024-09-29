// CommonJS because OpenApiValidator do not handle ES Modules
module.exports = {
  createUser: (req, res, next) => {
    import('./actions/users.js').then(({ createUser }) => {
      try {
        createUser(req, res, next);
      } catch (err) {
        next(err);
      }
    });
  },
  listUsers: (req, res, next) => {
    import('./actions/users.js').then(({ listUsers }) => {
      try {
        listUsers(req, res, next);
      } catch (err) {
        next(err);
      }
    });
  },
  logUser: (req, res, next) => {
    import('./actions/users.js').then(({ logUser }) => {
      try {
        logUser(req, res, next);
      } catch (err) {
        next(err);
      }
    });
  },
};

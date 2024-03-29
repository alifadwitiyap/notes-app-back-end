module.exports = (handler) => [
    {
        method: 'POST',
        path: '/users',
        handler: handler.postUserHandler,
    },
    {
        method: 'GET',
        path: '/users/{id}',
        handler: handler.getUserByIdHandler,
    }, {
        method: 'GET',
        path: '/users',
        handler: handler.getUsersByUsernameHandler,
    },
];
const express = require('express');
const router = express.Router();
const Joi = require('joi');
const validateRequest = require('_middleware/validate-request');
const Role = require('_helpers/role');
const userService = require('./user.service');


router.get('/', getAll);
router.get('/profile/:id', getById);
router.post('/', createSchema, create);
router.put('/profile/:id', updateSchema, update);
router.put('/profile/password/:id', updateSchema, update);
router.delete('/:id', _delete);
router.get('/:id/activities', getActivities);


module.exports = router;

function getAll(req, res, next) {
    userService.getAll()
    .then(users => res.json(users))
    .catch(next);
}
function getById(req, res, next) {
    userService.getById(req.params.id)
    .then(user => res.json(user))
    .catch(next);
}
function create(req, res, next) {
    userService.create(req.body)
    .then(() => res.json({ message: 'User created'}))
    .catch(next);
}
// RIGHT: This catches the user object from the service and sends it
function update(req, res, next) {
    userService.update(req.params.id, req.body)
        .then(user => res.json(user)) 
        .catch(next);
}
function _delete(req, res, next) {
    userService.delete(req.params.id)
    .then(() => res.json({ message: 'User deleted' }))
    .catch(next);
}
function getActivities(req, res, next) {
    userService.getUserActivities(req.params.id, req.query)
        .then(activities => res.json(activities))
        .catch(next);
}
function createSchema(req, res, next) {
    const schema = Joi.object({
        title: Joi.string().required(),
        firstName: Joi.string().required(),
        lastName: Joi.string().required(),
        role: Joi.string().valid(Role.Admin, Role.User).required(),
        email: Joi.string().email().required(),
        profilePic: Joi.string().required(),
        password: Joi.string().min(6).required(),     
        confirmPassword: Joi.string().valid(Joi.ref('password')).required()

    });
    validateRequest(req, next, schema);

}
function updateSchema(req, res, next) {
    const schema = Joi.object({
        title: Joi.string().empty(''),
        firstName: Joi.string().empty(''),
        lastName: Joi.string().empty(''),
        role: Joi.string().valid(Role.Admin, Role.User).empty(''),
        email: Joi.string().email().required(),
        profilePic: Joi.string().empty(''),
        currentPassword: Joi.string().min(6).optional(),
        newPassword: Joi.string().min(6).optional(),
        confirmPassword: Joi.string().valid(Joi.ref('newPassword')).optional(),
        updatelog:Joi.string().min(6).optional(),
    }).with('newPassword', 'confirmPassword');
    validateRequest(req, next, schema);
}   

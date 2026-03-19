const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('_helpers/db');
const { Sequelize, Op } = require('sequelize');

module.exports = {
    getAll,
    getById,
    create,
    update,
    _delete,
    search,
    searchAll,
    getPreferences,
    updatePreferences,
    changePass,
    login,
    logout,
    logActivity,
    getAllActivities,
    getUserActivities,
    deactivate,
    reactivate,
    getPermission,
    createPermission,
    clearAllLogs
};

//SIMPLE CRUD OPERATIONS
async function getAll() {
    return await db.User.findAll();
}

async function getById(id) {
    return await getUser(id);
} 

async function create(params) {
    if (await db.User.findOne({ where: { email: params.email } })) {
        throw `Email "${params.email}" is already registered`;
    }

    // FIX #6: Added username duplicate check to match the same logic in update()
    if (await db.User.findOne({ where: { username: params.username } })) {
        throw `Username "${params.username}" is already taken`;
    }
    
    const user = new db.User(params);
    user.passwordHash = await bcrypt.hash(params.password, 10);
    await user.save();

    // NEW LOGGING CODE
    // Logs the creation event with IP, Browser, and the user's email
    await logActivity(
        user.id, 
        'create', 
        `IP Address: ${params.ipAddress}, Browser Info: ${params.browserInfo}, Details: Created user with email: ${user.email}`
    );
}

async function update(id, params) {
    const user = await db.User.findByPk(id);
    const oldData = { ...user.get() }; // Snapshot before change

    // 1. Identify what actually changed
    const changedFields = [];
    for (const key in params) {
        if (params[key] !== oldData[key] && key !== 'password' && key !== 'confirmPassword') {
            changedFields.push(`${key}: ${oldData[key]} -> ${params[key]}`);
        }
    }

    // 2. Perform the update
    Object.assign(user, params);
    await user.save();

    // 3. Create a detailed log message
    const detailString = `IP: ${params.ipAddress}, Browser: ${params.browserInfo}${changedFields.length > 0 ? ', Details: Updated fields: ' + changedFields.join(', ') : ''}`;

    await logActivity(id, 'update', detailString, oldData);

    return user.get();

    // Username unique check
    if (params.username && user.username !== params.username) {
        if (await db.User.findOne({ where: { username: params.username } })) {
            throw `Username "${params.username}" is already taken`;
        }
    }

    // Hash password if provided
    if (params.password) {
        params.passwordHash = await bcrypt.hash(params.password, 10);
    }

    // Audit: Track changes
    for (const key in params) {
        if (params.hasOwnProperty(key) && !nonUserFields.includes(key) && key !== 'password') {
            if (oldData[key] !== params[key] && params[key] !== undefined) {
                updatedFields.push(`${key}: ${oldData[key]} -> ${params[key]}`);
            }
        }
    }

    Object.assign(user, params);
    await user.save();

    const updateDetails = updatedFields.length > 0 
        ? `Updated fields: ${updatedFields.join(', ')}` 
        : 'No fields changed';

    await logActivity(user.id, 'update', params.ipAddress, params.browserInfo, updateDetails);
}

async function _delete(id) {
    const user = await getUser(id);
    await db.ActivityLog.destroy({ where: { userId: id } });
    await user.destroy();
} 

async function _delete(id, params) {
    const user = await db.User.findByPk(id);
    if (!user) throw 'User not found';

    // 1. Create the final "Delete" log
    await logActivity(
        id, 
        'delete', 
        `IP Address: ${params.ipAddress}, Browser Info: ${params.browserInfo}, Details: Deleted user: ${user.email}`
    );

    // 2. MANUALLY delete all logs for this user so the constraint doesn't fail
    await db.ActivityLog.destroy({ where: { userId: id } });

    // 3. Now delete the user
    await user.destroy();
}

//SEARCH FUNCTIONS
async function searchAll(query) {
    const users = await db.User.findAll({
        where: {
            [Op.or]: [
                { email: { [Op.like]: `%${query}%` } },
                { title: { [Op.like]: `%${query}%` } },
                { firstName: { [Op.like]: `%${query}%` } },
                { lastName: { [Op.like]: `%${query}%` } },
                { role: { [Op.like]: `%${query}%` } }
            ]
        }
    });
    return users;
}

async function search(params) {
    const whereClause = {};

    if (params.email) whereClause.email = { [Op.like]: `%${params.email}%` };
    if (params.title) whereClause.title = { [Op.like]: `%${params.title}%` };
    if (params.role) whereClause.role = { [Op.like]: `%${params.role}%` };
    if (params.status) whereClause.status = params.status;

    // FIX #4/#5: Added missing firstName, lastName, dateCreated, lastDateLogin filters
    if (params.firstName) whereClause.firstName = { [Op.like]: `%${params.firstName}%` };
    if (params.lastName) whereClause.lastName = { [Op.like]: `%${params.lastName}%` };

    if (params.dateCreated) {
        whereClause.createdAt = {
            [Op.between]: [
                new Date(params.dateCreated),
                new Date(new Date(params.dateCreated).setHours(23, 59, 59, 999))
            ]
        };
    }

    if (params.lastDateLogin) {
        whereClause.lastDateLogin = {
            [Op.between]: [
                new Date(params.lastDateLogin),
                new Date(new Date(params.lastDateLogin).setHours(23, 59, 59, 999))
            ]
        };
    }
    
    if (params.fullName) {
        whereClause[Op.and] = Sequelize.where(
            Sequelize.fn('CONCAT', Sequelize.col('firstName'), ' ', Sequelize.col('lastName')),
            { [Op.like]: `%${params.fullName}%` }
        );
    }

    return await db.User.findAll({ where: whereClause });
}

//ACCOUNT STATUS MANAGEMENT
async function deactivate(id) {
    const user = await getUser(id);
    user.status = 'deactivated';
    await user.save();
}

async function reactivate(id) {
    const user = await getUser(id);
    user.status = 'active';
    await user.save();
}

//PREFERENCES AND PERMISSIONS
async function getPreferences(id) {
    return await db.User.findByPk(id, { attributes: ['id', 'theme', 'notifications', 'language'] });
}

async function updatePreferences(id, params) {
    const user = await getUser(id);
    Object.assign(user, params);
    await user.save();
}

async function getPermission(id) {
    return await db.User.findByPk(id, { attributes: ['id', 'permission', 'updatedAt'] });
}

async function createPermission(id, params) {
    const user = await getUser(id);
    Object.assign(user, params); 
    await user.save();
}

//AUTHENTICATION AND ACTIVITY LOGGING
async function changePass(id, params) {
    const user = await db.User.scope('withHash').findByPk(id);
    if (!user) throw 'User does not exist';

    if (!await bcrypt.compare(params.currentPassword, user.passwordHash)) {
        throw 'Current password is incorrect';
    }

    user.passwordHash = await bcrypt.hash(params.newPassword, 10);
    await user.save();

    await logActivity(user.id, 'change pass', params.ipAddress, params.browserInfo);
}

async function login(params) {
    const user = await db.User.scope('withHash').findOne({ where: { email: params.email } });
    
    if (!user || user.status === 'deactivated' || !await bcrypt.compare(params.password, user.passwordHash)) {
        throw 'Invalid email or password';
    }

    const token = jwt.sign({ id: user.id }, process.env.SECRET, { expiresIn: '7d' });

    user.lastDateLogin = new Date();
    await user.save();

    await logActivity(user.id, 'login', params.ipAddress, params.browserInfo);

    return { ...user.get(), token };
}

async function logout(id, params) {
    await logActivity(id, 'logout', params.ipAddress, params.browserInfo, 'User logged out');
    return { message: 'User logged out successfully' };
}

//ACTIVITY LOGGING
async function logActivity(userId, actionType, actionDetails, previousValue = null) {
    await db.ActivityLog.create({
        userId,
        actionType,
        actionDetails,
        previousValue: previousValue ? JSON.stringify(previousValue) : null
    });


    // Cleanup: Keep only last 10 logs per user
    const logCount = await db.ActivityLog.count({ where: { userId } });
    if (logCount > 10) {
        const oldestLogs = await db.ActivityLog.findAll({
            where: { userId },
            order: [['timestamp', 'ASC']], 
            limit: logCount - 10 
        });
        await db.ActivityLog.destroy({ where: { id: oldestLogs.map(l => l.id) } });
    }
}

async function getUserActivities(userId, filters = {}) {
    const { Op } = require('sequelize'); // Ensures Op is available for your filters
    let whereClause = { userId };

    if (filters.actionType) {
        whereClause.actionType = { [Op.like]: `%${filters.actionType}%` };
    }
    if (filters.startDate || filters.endDate) {
        whereClause.timestamp = {
            [Op.between]: [
                filters.startDate ? new Date(filters.startDate) : new Date(0),
                filters.endDate ? new Date(filters.endDate) : new Date()
            ]
        };
    }

    // ADDED: order: [['timestamp', 'DESC']] to show newest logs first
    return await db.ActivityLog.findAll({ 
        where: whereClause,
        order: [['timestamp', 'DESC']] 
    });
}

async function getAllActivities() {
    return await db.ActivityLog.findAll({ 
        order: [['timestamp', 'DESC']] // This puts the newest logs at the top
    });
}

async function clearAllLogs() {
    await db.ActivityLog.destroy({ 
        where: {}, 
        truncate: true 
    });
}
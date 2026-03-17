const { Op } = require('sequelize');
const bcrypt = require('bcryptjs');
const db = require('_helpers/db');

module.exports = {
    getAll,
    getById,
    create,
    update,
    delete: _delete,
    getUserActivities,
    logActivity
};
    
async function getUserActivities(userId, filters = {}) {
    const user = await getUser(userId);
    if (!user) throw new Error('User not found');

    let whereClause = { userId };

    // Apply optional filters such as action type and timestamp range
    if (filters.actionType) {
      whereClause.actionType = { [Op.like]: `%${filters.actionType}%` };
    }
    if (filters.startDate || filters.endDate) {
        const startDate = filters.startDate ? new Date(filters.startDate) : new Date(0);
        const endDate = filters.endDate ? new Date(filters.endDate) : new Date();
        whereClause.timestamp = { [Op.between]: [startDate, endDate] };
    }

    try {
        const activities = await db.ActivityLog.findAll({ where: whereClause });
        return activities;
    } catch (error) {
        console.error('Error retrieving activities:', error);
        throw new Error('Error retrieving activities');
    }

}

async function logActivity(userId, actionType, ipAddress, browserInfo, updateDetails = '') {
    try {

        const db = require('_helpers/db');

        // Add this check to prevent the 500 error crash
        if (!db.ActivityLog) {
            console.error("Database not initialized: db.ActivityLog is undefined");
            return; 
        }
        
        
        // Create a new log entry in the 'activity_log' table
        await db.ActivityLog.create({
            userId,
            actionType,
            actionDetails: `IP Address: ${ipAddress}, Browser Info: ${browserInfo}, Details: ${updateDetails}`,
            timestamp: new Date()
        });

        // Count the number of logs for the user
        const logCount = await db.ActivityLog.count({ where: { userId } });

        if (logCount > 10) {
            // Find and delete the oldest logs
            const logsToDelete = await db.ActivityLog.findAll({
                where: { userId },
                order: [['timestamp', 'ASC']], 
                limit: logCount - 10 
            });

            if (logsToDelete.length > 0) {
                const logIdsToDelete = logsToDelete.map(log => log.id);

                await db.ActivityLog.destroy({
                    where: {
                        id: {
                            [Op.in]: logIdsToDelete
                        }
                    }
                });
                console.log(`Deleted ${logIdsToDelete.length} oldest log(s) for user ${userId}.`);
            }
        }
    } catch (error) {
        console.error('Error logging activity:', error);
        throw error;
    }
}

async function getAll() {
    return await db.User.findAll();
}

async function getById(id) {
    return await getUser(id);
}

async function create(params) {
    
    if (await db.User.findOne({ where: { email: params.email } })) {
        throw 'Email "' + params.email + '" is already registered';
    }
    

    const user = new db.User(params);
    user.passwordHash = await bcrypt.hash(params.password, 10);
    await user.save();
}

async function update(id, params) {
    // Extract password fields from params if they exist
    const { currentPassword, newPassword, confirmPassword, ...updateFields } = params;

    // Fetch the user with password hash
    const user = await db.User.scope('withHash').findByPk(id);
   

    if (!user) {
        throw 'User not found';
    }

     // Change 'Register' to 'Update' and change the message
    await logActivity(user.id, 'Update', '127.0.0.1', 'Thunder Client', `User updated: ${user.email}`);

    // Check if username has changed and is available
    const usernameChanged = updateFields.username && user.username !== updateFields.username;
    if (usernameChanged && await db.User.findOne({ where: { username: updateFields.username } })) {
        throw `Username "${updateFields.username}" is already taken`;
    }

    // If a password change is requested, validate current and new passwords
    if (currentPassword && newPassword) {
        const isMatch = await bcrypt.compare(currentPassword, user.passwordHash);
        if (!isMatch) {
            throw 'Current password is incorrect';
        }

        if (await bcrypt.compare(newPassword, user.passwordHash)) {
            throw 'New password cannot be the same as the current password';
        }

        if (newPassword !== confirmPassword) {
            throw 'New password and confirm password do not match';
        }

        // Hash the new password and update the user
        user.passwordHash = await bcrypt.hash(newPassword, 10);
    }

    // Apply other updates from params
    Object.assign(user, updateFields);

    // Save the user
    await user.save();
}


async function _delete(id) {
    const user = await getUser(id);

    await logActivity(user.id, 'Delete', '127.0.0.1', 'Thunder Client', `Account deleted for ${user.email}`);

    await user.destroy();
}

async function getUser(id) {
    const user = await db.User.findByPk(id);
    if (!user) throw 'User not found';
    return user;
}

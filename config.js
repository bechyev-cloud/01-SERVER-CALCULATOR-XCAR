/*
 * XCAR SERVER CONFIG
 *
 * Этот файл специально используется вместо .env.
 * Его можно хранить в GitHub вместе с проектом.
 *
 * ВАЖНО: если на Render заданы Environment Variables, они имеют приоритет
 * над значениями ниже. Поэтому существующая схема деплоя не ломается.
 */
module.exports = {
  port: 3000,
  dbFile: './xcar.sqlite',
  backupDir: './backups',
  backupRetention: 30,

  // Авторизация администратора.
  // ЗАМЕНИ CHANGE_ME_NOW на свой пароль, если не используешь Render Variables.
  adminUser: 'admin',
  adminPassword: 'CHANGE_ME_NOW',

  clientServerUrl: 'https://zero1-server-calculator-xcar.onrender.com',

  monthPrice: 500,
  payBank: 'Сбербанк',
  payCard: '',
  payRecipient: '',
  payPhone: ''
};

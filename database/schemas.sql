
PRAGMA foreign_keys = ON;

CREATE TABLE roles (
    role_id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name TEXT NOT NULL UNIQUE
);

INSERT INTO roles (role_name) VALUES ('ROLE_ADMIN');
INSERT INTO roles (role_name) VALUES ('ROLE_MANAGER');
INSERT INTO roles (role_name) VALUES ('ROLE_USER');



CREATE TABLE users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,

    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    address TEXT,
    date_of_birth DATE NOT NULL,

    role_id INTEGER NOT NULL,

    is_active INTEGER NOT NULL DEFAULT 1,      -- 1 = active, 0 = inactive
    is_suspended INTEGER NOT NULL DEFAULT 0,   -- 1 = suspended
    failed_attempts INTEGER NOT NULL DEFAULT 0,

    account_created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    password_expiry_date DATETIME,

    profile_picture BLOB,

    FOREIGN KEY (role_id)
        REFERENCES roles(role_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
);


CREATE TABLE password_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    password_hash TEXT NOT NULL,
    changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id)
        REFERENCES users(user_id)
        ON DELETE CASCADE
);


CREATE TABLE login_attempts (
    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username_attempted TEXT NOT NULL,
    attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    success INTEGER NOT NULL,   -- 1 = success, 0 = failure

    FOREIGN KEY (user_id)
        REFERENCES users(user_id)
        ON DELETE SET NULL
);


CREATE TABLE user_suspensions (
    suspension_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    reason TEXT,

    FOREIGN KEY (user_id)
        REFERENCES users(user_id)
        ON DELETE CASCADE
);


CREATE TABLE password_resets (
    reset_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    reset_token TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,

    FOREIGN KEY (user_id)
        REFERENCES users(user_id)
        ON DELETE CASCADE
);


CREATE TABLE user_requests (
    request_id INTEGER PRIMARY KEY AUTOINCREMENT,

    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    address TEXT,
    date_of_birth DATE NOT NULL,
    email TEXT NOT NULL,

    request_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'APPROVED', 'REJECTED' )),

    reviewed_by INTEGER,
    reviewed_at DATETIME,

    FOREIGN KEY (reviewed_by)
        REFERENCES users(user_id)
        ON DELETE SET NULL
);

CREATE INDEX idx_users_role ON users(role_id);
CREATE INDEX idx_login_user ON login_attempts(user_id);
CREATE INDEX idx_password_history_user ON password_history(user_id);
CREATE INDEX idx_suspension_user ON user_suspensions(user_id);

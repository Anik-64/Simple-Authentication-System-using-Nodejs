-- gen_userrolesetting (userroleno,userroletitle,description,ispublic)
CREATE TABLE gen_userrolesetting (
    userroleno SERIAL PRIMARY KEY,
    userroletitle varchar(50) NOT NULL,
    description varchar(511) DEFAULT NULL,
    ispublic SMALLINT DEFAULT 1
);

-- gen_userstatus (userstatusno, userstatustitle)
CREATE TABLE gen_userstatus (
    userstatusno SMALLINT PRIMARY KEY,
    userstatustitle VARCHAR(50) DEFAULT NULL
);

-- gen_peopleprimary (peopleno, peopleid, firstname, lastname, countrycode, contactno, nid, dob, gender, bloodgroup, email, street, postcode, country, profilepicurl, validated, createdatetime, faf_parentpeopleno)
CREATE TABLE gen_peopleprimary (
    peopleno SERIAL PRIMARY KEY,
    peopleid VARCHAR(63) DEFAULT NULL,
    firstname VARCHAR(127) NOT NULL,
    lastname VARCHAR(127) DEFAULT NULL,
    countrycode VARCHAR(5) DEFAULT '+880',
    contactno VARCHAR(20) NOT NULL,
    nid VARCHAR(20) DEFAULT NULL,
    dob DATE NOT NULL,
    gender VARCHAR(15) CHECK (gender IN ('Male', 'Female', 'Others', 'Not mentioned')) DEFAULT 'Not mentioned',
    -- gender ENUM('Male', 'Female', 'Others', 'Not mentioned') DEFAULT 'Not mentioned',
    bloodgroup CHAR(3) DEFAULT NULL,
    email VARCHAR(255) DEFAULT NULL,
    street VARCHAR(255) DEFAULT NULL,
    postcode INT DEFAULT NULL,
    country VARCHAR(63) DEFAULT NULL,
    profilepicurl VARCHAR(255) DEFAULT NULL,
    validated INT NOT NULL DEFAULT 1,
    createdatetime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    faf_parentpeopleno INT DEFAULT NULL,
    CONSTRAINT uk_peopleprimary_peopleid UNIQUE (peopleid),
    CONSTRAINT fk_peopleprimary_faf_parentpeopleno FOREIGN KEY (faf_parentpeopleno) REFERENCES gen_peopleprimary (peopleno) ON UPDATE CASCADE
);

-- gen_users (userno, peopleno, email, contactno, username, passphrase, authkey, userstatusno, ucreatedatetime, reset_pass_count, updatetime)
CREATE TABLE gen_users (
    userno SERIAL PRIMARY KEY,
    peopleno INT DEFAULT NULL,
    username VARCHAR(255) NOT NULL,
    passphrase VARCHAR(255) NOT NULL,
    authkey VARCHAR(255) DEFAULT NULL,
    userstatusno SMALLINT DEFAULT 1,
    ucreatedatetime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reset_pass_count INT DEFAULT 0,
    updatetime TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_users_username UNIQUE (username),
    CONSTRAINT fk_users_peopleno FOREIGN KEY (peopleno) REFERENCES gen_peopleprimary (peopleno) ON UPDATE CASCADE,
    CONSTRAINT fk_users_userstatusno FOREIGN KEY (userstatusno) REFERENCES gen_userstatus (userstatusno) ON UPDATE CASCADE
);

-- gen_userroles (userno, userroleno, validuntil)
CREATE TABLE gen_userroles (
    userno INT NOT NULL,
    userroleno SMALLINT NOT NULL,
    validuntil TIMESTAMP DEFAULT NULL,
    UNIQUE (userno, userroleno),
    CONSTRAINT fk_userroles_userroleno FOREIGN KEY (userroleno) REFERENCES gen_userrolesetting (userroleno) ON UPDATE CASCADE,
    CONSTRAINT fk_userroles_userno FOREIGN KEY (userno) REFERENCES gen_users (userno) ON UPDATE CASCADE
);

-- userrecovery (sl, userno, otp, via, recipent, sent_at, expries_at)
CREATE TABLE userrecovery (
    sl SERIAL PRIMARY KEY,
    userno INT NOT NULL,
    otp CHAR(6) NOT NULL,
    via CHAR(1) NOT NULL,  
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_userrecovery_userno FOREIGN KEY (userno) REFERENCES gen_users (userno) ON UPDATE CASCADE
);
COMMENT ON COLUMN userrecovery.via IS 'Email: 1, SMS: 2, App: 3';
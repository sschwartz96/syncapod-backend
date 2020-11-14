CREATE TABLE Users (
	id UUID PRIMARY KEY,
	email TEXT NOT NULL UNIQUE,
	username TEXT NOT NULL UNIQUE,
	birthdate DATE NOT NULL,
	password_hash BYTEA NOT NULL,
	created TIMESTAMPTZ NOT NULL,
	last_seen TIMESTAMPTZ NOT NULL
);

CREATE TABLE Sessions (
	id UUID PRIMARY KEY,
	user_id UUID NOT NULL REFERENCES Users(id) ON DELETE CASCADE,
	login_time TIMESTAMPTZ NOT NULL,
	last_seen_time TIMESTAMPTZ NOT NULL,
	expires TIMESTAMPTZ NOT NULL,
	user_agent TEXT NOT NULL
);

CREATE TABLE AuthCodes (
	code BYTEA PRIMARY KEY,
	client_id TEXT NOT NULL,
	user_id UUID NOT NULL REFERENCES Users(id) ON DELETE CASCADE,
	scope TEXT NOT NULL,
	expires TIMESTAMPTZ NOT NULL
);

CREATE TABLE AccessTokens (
	token BYTEA PRIMARY KEY,
	auth_code BYTEA NOT NULL REFERENCES AuthCodes(code) ON DELETE CASCADE,
	refresh_token BYTEA NOT NULL,
	user_id UUID NOT NULL REFERENCES Users(id) ON DELETE CASCADE,
	created TIMESTAMPTZ NOT NULL,
	expires INT NOT NULL
);

CREATE TABLE Podcasts (
	-- REQUIRED TAGS
	id UUID PRIMARY KEY,
	title TEXT NOT NULL,
	description TEXT NOT NULL,
	image_url TEXT NOT NULL,
	language TEXT NOT NULL,
	category INTEGER[] NOT NULL,
	explicit TEXT NOT NULL,
	-- RECOMMENDED TAGS
	author TEXT,
	link_url TEXT,
	owner_name TEXT,
	owner_email TEXT,
	-- SITUATIONAL TAGS
	episodic BOOLEAN DEFAULT TRUE, 
	copyright TEXT,
	block BOOLEAN,
	complete BOOLEAN,
	-- RSS/OTHER
	pub_date TIMESTAMPTZ,
	keywords TEXT,
	summary TEXT,
	rss_url TEXT NOT NULL
);

CREATE TABLE Episode (
	-- REQUIRED TAGS
	id UUID PRIMARY KEY,
	title TEXT NOT NULL,
	enclosure_url TEXT NOT NULL,
	enclosure_length BIGINT NOT NULL,
	enclosure_type TEXT NOT NULL,
	-- RECOMMENDED TAGS
	pub_date TIMESTAMPTZ,
	description TEXT,
	duration BIGINT,
	link_url TEXT,
	image_url TEXT,
	explicit TEXT,
	-- SITUATIONAL TAGS
	episode INT,
	season INT,
	episode_type TEXT, -- Full, Trailer, Bonus
	block BOOLEAN,
	-- OTHER
	summary TEXT,
	encoded TEXT,
	podcast_id UUID  NOT NULL REFERENCES Podcasts(id) ON DELETE CASCADE
);

CREATE TABLE Categories (
	id SERIAL,
	name TEXT NOT NULL,
	parent_id INTEGER NOT NULL REFERENCES Categories(id) ON DELETE CASCADE
);

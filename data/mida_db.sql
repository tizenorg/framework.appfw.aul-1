PRAGMA journal_mode = PERSIST;

CREATE TABLE IF NOT EXISTS mida ( 
	id INTEGER PRIMARY KEY, 
	pkg_name TEXT, 
	mime_type TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS svc ( 
	id INTEGER PRIMARY KEY, 
	pkg_name TEXT, 
	svc_name TEXT UNIQUE NOT NULL
);

DROP TABLE IF EXISTS system_svc;

CREATE TABLE IF NOT EXISTS system_svc ( 
	id INTEGER PRIMARY KEY, 
	svc_name TEXT UNIQUE NOT NULL
);


INSERT INTO system_svc(svc_name) VALUES ("create_alarm");
INSERT INTO system_svc(svc_name) VALUES ("open_calendar");
INSERT INTO system_svc(svc_name) VALUES ("create_event");
INSERT INTO system_svc(svc_name) VALUES ("view_event");
INSERT INTO system_svc(svc_name) VALUES ("take_picture");
INSERT INTO system_svc(svc_name) VALUES ("record_video");
INSERT INTO system_svc(svc_name) VALUES ("read_barcode");
INSERT INTO system_svc(svc_name) VALUES ("search_contact");
INSERT INTO system_svc(svc_name) VALUES ("create_email");
INSERT INTO system_svc(svc_name) VALUES ("view_email");
INSERT INTO system_svc(svc_name) VALUES ("browse_file");
INSERT INTO system_svc(svc_name) VALUES ("create_memo");
INSERT INTO system_svc(svc_name) VALUES ("view_memo");
INSERT INTO system_svc(svc_name) VALUES ("create_message");
INSERT INTO system_svc(svc_name) VALUES ("view_message");
INSERT INTO system_svc(svc_name) VALUES ("search");
INSERT INTO system_svc(svc_name) VALUES ("make_videocall");
INSERT INTO system_svc(svc_name) VALUES ("make_voicecall");
INSERT INTO system_svc(svc_name) VALUES ("record_voice");
INSERT INTO system_svc(svc_name) VALUES ("play_music");
INSERT INTO system_svc(svc_name) VALUES ("browse_web");
INSERT INTO system_svc(svc_name) VALUES ("update_facebook");
INSERT INTO system_svc(svc_name) VALUES ("update_twitter");
INSERT INTO system_svc(svc_name) VALUES ("open_ebook");


-- Applied automatically by the API (SQLAlchemy create_all). Kept here for DBA review. PostgreSQL.
CREATE TABLE IF NOT EXISTS state (
    id      integer PRIMARY KEY,
    version integer NOT NULL,
    body    text    NOT NULL
);

create index if not exists movie_title_idx on movies using gin (to_tsvector('simple', title));
create index if not exists movie_genres_idx on movies using gin (genres);


-- El panel de TrafficFlow se sirve en traffic.mobile-americas.com; tf.mobile-americas.com
-- son ahora los CLICS de MS-1 (decision de difgar, 2026-10-02). Con tf. aqui, el login
-- del panel fallaria por redirect_uri y el menu del admin (claim `apps`) llevaria al
-- redirect de clics.
--
-- Migracion NUEVA y no edicion de V5: las bases que ya aplicaron V5 fallarian por
-- checksum. Los de localhost:5174 (desarrollo) se conservan.
UPDATE auth_app
   SET url                       = 'https://traffic.mobile-americas.com',
       redirect_uris             = 'https://traffic.mobile-americas.com/callback,http://localhost:5174/callback',
       post_logout_redirect_uris = 'https://traffic.mobile-americas.com/,http://localhost:5174/',
       updated_at                = TIMESTAMP '2026-10-03 00:00:00'
 WHERE name = 'trafficflow';

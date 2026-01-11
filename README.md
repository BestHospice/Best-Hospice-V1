# Best Hospice

Static prototype that lets visitors enter a US ZIP code, zoom a live map, and see nearby hospice centers pulled from OpenStreetMap.

## Run it locally
1) Install deps: `npm install`  
2) Run migrations / generate Prisma client:  
   - `npx prisma generate`  
   - `npx prisma migrate dev --name init` (creates prisma/dev.db)  
3) Start server: `npm start` (default port 8080).  
4) Open http://localhost:8080 in your browser. The map and search rely on public OSM services, so internet access is required.

### Env vars
- `ADMIN_TOKEN_ADD` (default `TimetoProvideHelp12!`)  
- `ADMIN_TOKEN_REMOVE` (default `this221isHow45!toRemove398Them34!`)  
- `ADMIN_TOKEN_DASH` (default `lookForProviders177Now73!`)  
- `ADMIN_TOKEN_AUDIT` (defaults to DASH token)  
- `SENDGRID_API_KEY`, `SENDGRID_FROM_EMAIL`, `SENDGRID_REPLY_TO`  
- `TURNSTILE_SITE_KEY` (frontend; fetched from `/api/config/turnstile`)  
- `TURNSTILE_SECRET_KEY` (server-side Turnstile verification; `TURNSTILE_SECRET` is read as a fallback)  
- `IP_SALT` (hashing IPs for rate limiting)

## How it works
- Geocodes ZIP via Nominatim and centers the Leaflet map there.  
- Collects a guided questionnaire after ZIP entry (who needs care, schedule, services, contact email), then shows the map (Turnstile captcha required).  
- Queries the Overpass API for `healthcare=hospice` or `amenity=hospice` within ~60 miles (96.6 km).  
- Lists results, highlights markers, and keeps them sorted by distance.  
- Fetches provider records from `/api/providers` (JSON store) and merges them with live map data + featured defaults.  
- (If SendGrid configured) Emails the summary to nearby providers and logs lead + per-provider notification outcomes.  
- Providers stored in SQLite via Prisma; lead notifications, impressions, rate limits, and audit logs also stored in DB.

## Notes / Tweaks
- Radius: change `radiusKm` in `script.js` if you want a tighter or wider search.  
- Styling: `styles.css` holds all theme tweaks (colors, layout, responsive).  
- Attribution: Leaflet uses OpenStreetMap tiles; attribution is already in the map.  
- Politeness: For production, set a descriptive `User-Agent` and consider hosting your own Overpass endpoint or using a commercial geocoder to avoid rate limits.

## Next ideas
- Add filtering (in-patient vs. at-home, ratings, Medicaid/Medicare acceptance).  
- Persist user favorites and recent ZIPs in localStorage.  
- Replace public geocoder with a dedicated provider and cache results.  
- Add hero copy and trust markers (testimonials, accreditation badges) for launch polish.

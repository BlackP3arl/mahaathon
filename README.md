# mahathon26 judging

Score sheet for **mahathon26**, the one-day internal hackathon of the Maldives Pension Administration Office (25 November 2026, theme *Vaane*, 10 teams).

Three judges score each team on three areas, from 1 to 5 each:

| Area | What it measures |
|---|---|
| Wow factor | A surprising, magical or innovative feature, or a way of presenting it |
| Functionality | How well the solution covers the problem statement |
| Presentation | The 10-minute pitch and demo; joint delivery by the product owner and developers earns more |

That gives 15 points per judge and 45 per team. Ties are broken by Functionality, then Wow factor.

## How it works

- `index.html` is the whole app: one static page, no build step.
- Judges sign in with a seat (Judge 1, 2 or 3) and a 6-digit PIN. No accounts needed.
- An **Organiser** seat sees results and all notes but cannot score.
- Data lives in Supabase. The tables are closed to the API. Every read and write goes through functions that check the PIN on the server, so a judge can only change their own scores.
- After 5 wrong PINs, a seat locks for 5 minutes.
- Results refresh every 5 seconds and need a PIN, so teams can't see rankings early.
- Includes a 10-minute presentation timer and a CSV export of the results.

## Deploy

Host `index.html` on any static host (Vercel, Netlify, GitHub Pages, an internal web server). `vercel.json` adds no-index and no-cache headers on Vercel.

## Database

`supabase/schema.sql` creates the tables and functions, and the four seats with random PINs (printed once). The Supabase URL and publishable key at the top of the script in `index.html` are meant to be public; the PINs are what protect the scores. PINs are not stored in this repo.

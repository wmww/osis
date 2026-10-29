'use strict';
// Mock data for the UI mockup. No osis: plain objects, edited in memory.
// Kinds: note, event (may carry a body: event and note at once), contact, tag (a scope), view (a scope).

const DAY = 86400000;
const MONDAY = (() => { const d = new Date(); d.setHours(0, 0, 0, 0); return new Date(d - ((d.getDay() + 6) % 7) * DAY); })();
const at = (day, h, m = 0) => { const d = new Date(+MONDAY + day * DAY); d.setHours(h, m, 0, 0); return d; };
const ago = mins => new Date(Date.now() - mins * 60000);

const DATA = {
  monday: MONDAY,
  favorites: ['n-groceries', 'v-cal', 'g-lisbon', 'c-mara', 'e-jun', 'g-garden', 'v-people', 'n-ideas'],
  things: [
    // views
    { id: 'v-cal', kind: 'view', view: 'calendar', name: 'Calendar', color: '#f97316' },
    { id: 'v-people', kind: 'view', view: 'people', name: 'People', color: '#06b6d4' },
    { id: 'v-tags', kind: 'view', view: 'tags', name: 'Tags', color: '#8b5cf6' },
    { id: 'v-recent', kind: 'view', view: 'recent', name: 'Recent', color: '#64748b' },

    // tags
    { id: 'g-home', kind: 'tag', name: 'Home', color: '#f59e0b' },
    { id: 'g-work', kind: 'tag', name: 'Work', color: '#3b82f6' },
    { id: 'g-garden', kind: 'tag', name: 'Garden', color: '#22c55e', parent: 'g-home' },
    { id: 'g-recipes', kind: 'tag', name: 'Recipes', color: '#ef4444', parent: 'g-home' },
    { id: 'g-lisbon', kind: 'tag', name: 'Lisbon trip', color: '#ec4899', shared: ['Mara', 'Jun'] },
    { id: 'g-reading', kind: 'tag', name: 'Reading', color: '#a855f7' },

    // contacts
    { id: 'c-mara', kind: 'contact', name: 'Mara Okafor', color: '#e11d48', role: 'Friend · climbing', email: 'mara@okafor.me', phone: '+44 7700 900123', body: 'Allergic to walnuts. Birthday in March.' },
    { id: 'c-jun', kind: 'contact', name: 'Jun Takahashi', color: '#2563eb', role: 'Design lead', email: 'jun@studio-kei.jp', phone: '+81 90 1234 5678', body: '' },
    { id: 'c-ana', kind: 'contact', name: 'Ana Ribeiro', color: '#d97706', role: 'Our host in Lisbon', email: 'ana.ribeiro@mail.pt', phone: '+351 912 345 678', place: 'Alfama, Lisbon', body: 'Keys with the café downstairs.' },
    { id: 'c-theo', kind: 'contact', name: 'Theo Lindqvist', color: '#059669', role: 'Neighbour, allotment 14', email: 'theo.l@posteo.se', phone: '', body: 'Has spare seed potatoes every spring.' },
    { id: 'c-sam', kind: 'contact', name: 'Sam Patel', color: '#7c3aed', role: 'Engineering', email: 'sam@work.example', phone: '+1 415 555 0134', body: '' },
    { id: 'c-iris', kind: 'contact', name: 'Iris Novak', color: '#0891b2', role: 'Book club', email: 'iris@novak.cz', phone: '', body: '' },

    // notes
    { id: 'n-groceries', kind: 'note', name: 'Groceries', tags: ['g-home'], edited: ago(35),
      body: 'oat milk\neggs\nsourdough\nlemons\nbasil for the pesto\ncoffee beans (the Ethiopian one)' },
    { id: 'n-pesto', kind: 'note', name: 'Wild garlic pesto', tags: ['g-recipes'], edited: ago(60 * 26),
      body: '100 g wild garlic, 50 g parmesan, 40 g toasted pine nuts (not walnuts, Mara), olive oil until loose, lemon zest.\n\nBlitz briefly. Keeps a week under a layer of oil.' },
    { id: 'n-tomatoes', kind: 'note', name: 'Tomato varieties', tags: ['g-garden'], edited: ago(60 * 50),
      body: 'Sungold: sweetest, splits after rain\nBlack Krim: great flavour, low yield\nGardener\'s Delight: reliable\n\nTry San Marzano for sauce next year. Ask Theo about blight-resistant ones.', with: ['c-theo'] },
    { id: 'n-compost', kind: 'note', name: 'Compost notes', tags: ['g-garden'], edited: ago(60 * 24 * 9),
      body: 'Browns to greens about 3:1. Turn every two weeks. The far bin is ready in May.' },
    { id: 'n-itinerary', kind: 'note', name: 'Itinerary', tags: ['g-lisbon'], edited: ago(60 * 3),
      body: 'Thu: land 10:40, bags to Ana\'s, lunch at the market\nFri: tram 28, Alfama, miradouro at sunset\nSat: Sintra day trip\nSun: pastéis de nata class, flight 19:55', with: ['c-ana'] },
    { id: 'n-packing', kind: 'note', name: 'Packing list', tags: ['g-lisbon'], edited: ago(60 * 5),
      body: 'walking shoes\nsunscreen\nadapter (EU)\nlight jacket for Sintra\nbook for the flight' },
    { id: 'n-q4', kind: 'note', name: 'Q4 planning', tags: ['g-work'], edited: ago(60 * 20),
      body: 'Ship the sync redesign before December freeze.\nHire: one more backend person.\nOffsite: Lisbon? (ha)', with: ['c-jun', 'c-sam'] },
    { id: 'n-books', kind: 'note', name: 'Books to read', tags: ['g-reading'], edited: ago(60 * 24 * 4),
      body: 'The Dispossessed: Le Guin\nPiranesi: Clarke\nThe Mushroom at the End of the World: Tsing\nBraiding Sweetgrass: Kimmerer' },
    { id: 'n-dispossessed', kind: 'note', name: 'On The Dispossessed', tags: ['g-reading'], edited: ago(60 * 24 * 2),
      body: 'Anarres as a society that keeps having to re-choose its openness. Shevek\'s walls. For book club: is the ambiguous utopia still ambiguous?', with: ['c-iris'] },
    { id: 'n-ideas', kind: 'note', name: 'Ideas', edited: ago(12),
      body: 'A calendar that shows what I wrote that day, not just what I planned.\nTags as colours of the whole UI?\nShared shopping list with Mara for the trip.' },

    // events (some carry notes too)
    { id: 'e-standup', kind: 'event', name: 'Team standup', tags: ['g-work'], start: at(0, 9, 30), end: at(0, 9, 45), place: 'Video call', edited: ago(60 * 70) },
    { id: 'e-dentist', kind: 'event', name: 'Dentist', start: at(0, 16, 0), end: at(0, 16, 45), place: 'Bridge St Clinic', edited: ago(60 * 24 * 12) },
    { id: 'e-jun', kind: 'event', name: '1:1 with Jun', tags: ['g-work'], start: at(1, 11, 0), end: at(1, 11, 30), place: 'Room 3B', with: ['c-jun'], edited: ago(90),
      body: 'Agenda\n- feedback on the tags prototype\n- hiring loop\n- her offsite idea\n\nNotes\nWants colour to come from data, not chrome. Agrees on fewer, bigger views.' },
    { id: 'e-mara', kind: 'event', name: 'Dinner with Mara', tags: ['g-home'], start: at(1, 19, 0), end: at(1, 21, 30), place: 'Tavola, Kings Rd', with: ['c-mara'], edited: ago(60 * 30) },
    { id: 'e-seeds', kind: 'event', name: 'Seed swap', tags: ['g-garden'], start: at(2, 10, 0), end: at(2, 12, 0), place: 'Library, hall 2', with: ['c-theo'], edited: ago(60 * 24 * 3),
      body: 'Bring: spare Sungold seeds, runner beans. Looking for: San Marzano, borlotti.' },
    { id: 'e-club', kind: 'event', name: 'Book club', tags: ['g-reading'], start: at(2, 19, 30), end: at(2, 21, 0), place: 'Iris\'s flat', with: ['c-iris'], edited: ago(60 * 24 * 6) },
    { id: 'e-flight', kind: 'event', name: 'Flight to Lisbon', tags: ['g-lisbon'], start: at(3, 7, 10), end: at(3, 10, 40), place: 'LGW → LIS, TP1331', edited: ago(60 * 24) },
    { id: 'e-tram', kind: 'event', name: 'Tram 28 + Alfama', tags: ['g-lisbon'], start: at(4, 10, 0), end: at(4, 14, 0), place: 'Martim Moniz', with: ['c-ana'], edited: ago(60 * 8) },
    { id: 'e-sintra', kind: 'event', name: 'Sintra day trip', tags: ['g-lisbon'], start: at(5, 9, 0), end: at(5, 18, 0), place: 'Rossio station', edited: ago(60 * 8) },
    { id: 'e-nata', kind: 'event', name: 'Pastéis de nata class', tags: ['g-lisbon', 'g-recipes'], start: at(6, 11, 0), end: at(6, 13, 0), place: 'Rua da Prata 12', edited: ago(60 * 9),
      body: 'Write the recipe down properly this time.' },
  ],
};

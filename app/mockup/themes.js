'use strict';
// A theme is only these parameters; engine.css implements every enum value once. The six built-in themes are
// defaults: any combination is a theme. main is the colour used when the content gives none.
const THEME_PARAMS = [
  { k: 'bgLight', type: 'color', label: 'Background (light)' },
  { k: 'bgDark', type: 'color', label: 'Background (dark)' },
  { k: 'surfaceLight', type: 'color', label: 'Surface (light)' },
  { k: 'surfaceDark', type: 'color', label: 'Surface (dark)' },
  { k: 'bgTint', type: 'range', label: 'Content colour in background', min: 0, max: 1, step: .05 },
  { k: 'background', label: 'Background', opts: ['flat', 'field', 'curves', 'sky', 'grid', 'dots', 'shapes', 'lines', 'beams', 'grass'] },
  { k: 'panelOpacity', type: 'range', label: 'Panel opacity', min: 0, max: 1, step: .05 },
  { k: 'panelBlur', type: 'range', label: 'Panel blur', min: 0, max: 40, step: 2 },
  { k: 'radius', type: 'range', label: 'Corner radius', min: 0, max: 28, step: 1 },
  { k: 'outline', type: 'range', label: 'Outline width', min: 0, max: 3, step: .5 },
  { k: 'elevation', label: 'Elevation', opts: ['none', 'soft', 'hard'] },
  { k: 'finish', label: 'Finish', opts: ['flat', 'gloss', 'bevel'] },
  { k: 'iconShape', label: 'Icons', opts: ['circle', 'rounded', 'square'] },
  { k: 'tileFill', label: 'Tile fill', opts: ['surface', 'wash', 'solid'] },
  { k: 'tileMark', label: 'Tile mark', opts: ['none', 'stripe', 'corner'] },
  { k: 'selection', label: 'Selection', opts: ['soft', 'solid', 'slant'] },
  { k: 'font', label: 'Font', opts: ['system', 'humanist', 'classic', 'grotesk', 'rounded'] },
  { k: 'weight', type: 'range', label: 'Title weight', min: 300, max: 900, step: 100 },
  { k: 'labels', label: 'Labels', opts: ['plain', 'caps', 'big', 'mono'] },
  { k: 'accent', label: 'Accent', opts: ['none', 'bar', 'rule', 'slash'] },
];

// the colour used where a screen has none of its own
const NEUTRAL_MAIN = '#8b90a0';

const THEMES = [
  { id: 'frost', name: 'Frost', desc: 'Calm and open: content straight on a lightly tinted background with two soft curves, soft cards, round icons.',
    bgLight: '#f2f3f7', bgDark: '#0f1117', surfaceLight: '#ffffff', surfaceDark: '#1f2129', bgTint: .15, background: 'curves',
    panelOpacity: 0, panelBlur: 0, radius: 18, outline: 0, elevation: 'soft', finish: 'flat', iconShape: 'circle',
    tileFill: 'surface', tileMark: 'none', selection: 'soft', font: 'system', weight: 700, labels: 'plain', accent: 'none' },
  { id: 'glass', name: 'Glass', desc: 'A sky in the content colour with a light swoosh, frosted panels, gel tiles and selection.',
    bgLight: '#e6eef8', bgDark: '#07101e', surfaceLight: '#ffffff', surfaceDark: '#18223a', bgTint: .55, background: 'sky',
    panelOpacity: .55, panelBlur: 24, radius: 14, outline: 0, elevation: 'soft', finish: 'gloss', iconShape: 'circle',
    tileFill: 'solid', tileMark: 'none', selection: 'solid', font: 'humanist', weight: 600, labels: 'plain', accent: 'none' },
  { id: 'workstation', name: 'Workstation', desc: 'Bevelled panels on a grid, title bars, tag colour as a stripe.',
    bgLight: '#d4d4e2', bgDark: '#0d0e18', surfaceLight: '#c4c2d6', surfaceDark: '#2b2942', bgTint: .2, background: 'grid',
    panelOpacity: 1, panelBlur: 0, radius: 0, outline: 1, elevation: 'hard', finish: 'bevel', iconShape: 'square',
    tileFill: 'surface', tileMark: 'stripe', selection: 'solid', font: 'classic', weight: 700, labels: 'mono', accent: 'bar' },
  { id: 'memphis', name: 'Memphis', desc: 'Paper, thick outlines, hard offset shadows, washed tiles, three shapes.',
    bgLight: '#f5eedf', bgDark: '#1b1a20', surfaceLight: '#fffdf7', surfaceDark: '#26242c', bgTint: .12, background: 'shapes',
    panelOpacity: 1, panelBlur: 0, radius: 14, outline: 2.5, elevation: 'hard', finish: 'flat', iconShape: 'circle',
    tileFill: 'wash', tileMark: 'none', selection: 'soft', font: 'grotesk', weight: 900, labels: 'caps', accent: 'none' },
  { id: 'slate', name: 'Slate', desc: 'Square and flat: solid colour tiles straight on the background, light big type, a rule in the content colour.',
    bgLight: '#f2f2f2', bgDark: '#0f0f0f', surfaceLight: '#ffffff', surfaceDark: '#1d1d1d', bgTint: .1, background: 'flat',
    panelOpacity: 0, panelBlur: 0, radius: 0, outline: 0, elevation: 'none', finish: 'flat', iconShape: 'square',
    tileFill: 'solid', tileMark: 'none', selection: 'solid', font: 'humanist', weight: 300, labels: 'big', accent: 'rule' },
  { id: 'cel', name: 'Cel', desc: 'Flat on white or dark grey; colour on tiles and accents, slanted selection, bold lines.',
    bgLight: '#fbfbfc', bgDark: '#222228', surfaceLight: '#ffffff', surfaceDark: '#2b2b33', bgTint: .06, background: 'lines',
    panelOpacity: 1, panelBlur: 0, radius: 12, outline: 0, elevation: 'soft', finish: 'flat', iconShape: 'circle',
    tileFill: 'surface', tileMark: 'corner', selection: 'slant', font: 'rounded', weight: 800, labels: 'caps', accent: 'slash' },
];

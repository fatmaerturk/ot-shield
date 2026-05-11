// HMGCC Co-Creation Proposal — OTShield
// "Smart Personal Assistant for Security Researchers"
//
// USAGE:
//   npm install docx
//   node build_proposal.js
// Output: OTShield_HMGCC_Proposal.docx in current directory.

const fs = require('fs');
const path = require('path');
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, LevelFormat, TabStopType, TabStopPosition,
  HeadingLevel, BorderStyle, WidthType, ShadingType, PageNumber, PageBreak
} = require('docx');

// ---- Style helpers ----
const PURPLE = "5B2C8A";
const PURPLE_LIGHT = "EDE3F5";
const DARK = "1F1F1F";
const GREY = "595959";
const GREY_LIGHT = "F2F2F2";
const ACCENT = "7E3FBF";

const border = (color = "CCCCCC") => ({ style: BorderStyle.SINGLE, size: 4, color });
const allBorders = (color = "CCCCCC") => ({
  top: border(color), bottom: border(color), left: border(color), right: border(color),
});

const p = (text, opts = {}) => new Paragraph({
  spacing: { after: 80, line: 280 },
  ...opts,
  children: [new TextRun({ text, ...(opts.run || {}) })],
});

const pRuns = (runs, opts = {}) => new Paragraph({
  spacing: { after: 80, line: 280 },
  ...opts,
  children: runs,
});

const h1 = (text) => new Paragraph({
  heading: HeadingLevel.HEADING_1,
  spacing: { before: 160, after: 100 },
  children: [new TextRun({ text, bold: true, color: PURPLE, size: 26 })],
});

const h2 = (text) => new Paragraph({
  heading: HeadingLevel.HEADING_2,
  spacing: { before: 120, after: 60 },
  children: [new TextRun({ text, bold: true, color: DARK, size: 22 })],
});

const bullet = (text, level = 0, runs = null) => new Paragraph({
  numbering: { reference: "bullets", level },
  spacing: { after: 40, line: 260 },
  children: runs || [new TextRun({ text, size: 20 })],
});

const cell = (children, opts = {}) => new TableCell({
  borders: allBorders("BFBFBF"),
  margins: { top: 80, bottom: 80, left: 120, right: 120 },
  width: opts.width ? { size: opts.width, type: WidthType.DXA } : undefined,
  shading: opts.shade ? { fill: opts.shade, type: ShadingType.CLEAR } : undefined,
  verticalAlign: "center",
  children: Array.isArray(children) ? children : [children],
});

const tcText = (text, opts = {}) => new Paragraph({
  spacing: { after: 0, line: 240 },
  alignment: opts.align || AlignmentType.LEFT,
  children: [new TextRun({ text, bold: opts.bold, color: opts.color, size: opts.size || 18 })],
});

const tcBullet = (text) => new Paragraph({
  spacing: { after: 20, line: 240 },
  bullet: { level: 0 },
  children: [new TextRun({ text, size: 18 })],
});

// US Letter, ~1" margins
const PAGE = {
  size: { width: 12240, height: 15840 },
  margin: { top: 900, right: 1080, bottom: 900, left: 1080 },
};
const CONTENT_W = 12240 - 1080 - 1080;

const children = [];

// NOTE: This is the original script (pre-feedback-revisions).
// For the latest content (with Co-Creation section, system architecture,
// dual-use revisions, multilingual 12-week plan), use the .html or .md
// files in this folder. They reflect the final revised proposal.
//
// To regenerate this script with the latest content, ask Claude to
// rebuild it from the .md or .html version.

children.push(new Paragraph({
  children: [new TextRun({ text: "PLACEHOLDER — see HTML or MD file for latest content", color: PURPLE, bold: true, size: 28 })]
}));

const doc = new Document({
  creator: "OTShield",
  title: "HMGCC Co-Creation Proposal",
  styles: {
    default: { document: { run: { font: "Arial", size: 20 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 26, bold: true, font: "Arial", color: PURPLE },
        paragraph: { spacing: { before: 160, after: 100 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 22, bold: true, font: "Arial", color: DARK },
        paragraph: { spacing: { before: 120, after: 60 }, outlineLevel: 1 } },
    ],
  },
  numbering: {
    config: [
      { reference: "bullets",
        levels: [
          { level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 480, hanging: 280 } } } },
        ],
      },
    ],
  },
  sections: [{
    properties: { page: PAGE },
    children,
  }],
});

Packer.toBuffer(doc).then(buf => {
  const outPath = path.join(__dirname, "OTShield_HMGCC_Proposal.docx");
  fs.writeFileSync(outPath, buf);
  console.log("OK wrote " + outPath + " (" + buf.length + " bytes)");
});

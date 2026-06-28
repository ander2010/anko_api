# Download Endpoints Guide

This document shows how to use the PDF download endpoints from a client app.

## Auth

All endpoints below require:

- Header: `Authorization: Token <USER_TOKEN>`

Optional language header:

- `language: en` (default)
- `language: es`

---

## 1) Download Flashcards PDF

Endpoint:

- `GET /api/decks/{deck_id}/download-flashcards-pdf/`

### What this PDF includes

- Front pages render the flashcard `front` text
- Back pages render:
  - `back` text for text-only cards
  - `back_image` on top plus `back` text below when the card has an image back
- Existing text-only decks still work with no frontend change

### Query Parameters

- `print_mode` (optional): `book` or `notebook`
  - Default: `book`
- `disposition` (optional): `attachment` or `inline`
  - Default: `attachment`
  - `attachment`: forces file download (best for a **Download** button)
  - `inline`: opens PDF in browser viewer/tab when possible (best for a **Preview** button)

### UI Hint for `print_mode`

Use this short explanation in UI:

- `book`: normal page turn (left/right flip).  
  Recommended for most printers.
- `notebook`: top flip (like flipping a notebook up/down).  
  Use when backs appear inverted with `book`.

### cURL Examples

```bash
# EN, default print mode (book), force file download
curl -X GET "http://127.0.0.1:8000/api/decks/50/download-flashcards-pdf/?print_mode=book&disposition=attachment" \
  -H "Authorization: Token YOUR_TOKEN" \
  -H "language: en" \
  -o deck_50_en.pdf
```

```bash
# ES, notebook mode
curl -X GET "http://127.0.0.1:8000/api/decks/50/download-flashcards-pdf/?print_mode=notebook&disposition=attachment" \
  -H "Authorization: Token YOUR_TOKEN" \
  -H "language: es" \
  -o deck_50_es.pdf
```

### Frontend (fetch) Example

```js
async function downloadFlashcardsPdf(deckId, token, language = "en", printMode = "book") {
  const url = `/api/decks/${deckId}/download-flashcards-pdf/?print_mode=${printMode}&disposition=attachment`;
  const res = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Token ${token}`,
      language,
    },
  });

  if (!res.ok) throw new Error(`Download failed: ${res.status}`);

  const blob = await res.blob();
  const contentDisposition = res.headers.get("Content-Disposition") || "";
  const match = contentDisposition.match(/filename\\*?=(?:UTF-8''|")?([^\";]+)/i);
  const filename = match ? decodeURIComponent(match[1].replace(/"/g, "")) : `deck_${deckId}_${language}.pdf`;

  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}
```

---

## 1.1) Create Rich Flashcard With Back Image

Endpoint:

- `POST /api/decks/{deck_id}/add-rich-card/`

### Content Type

- `multipart/form-data`

### Purpose

Use this endpoint when the flashcard back can include:

- text only
- image only
- image plus explanatory text below

The older text-only bulk endpoint still exists and is unchanged:

- `POST /api/decks/add-flashcards/`

### Required Fields

- `front`

### Optional Fields

- `back`
- `notes`
- `back_image`

### Validation Rule

At least one of these must be present:

- `back`
- `back_image`

### Image Rules

- Allowed formats: `jpg`, `png`, `webp`
- Minimum resolution: `400x400`
- Maximum resolution before optimization target: `2000x2000`
- Maximum aspect ratio: `3.0:1`
- Target file limit: `3 MB`

### Auto Optimization

If the uploaded image is valid but too large by file size or dimensions, the backend will try to optimize it automatically:

- resize down to fit limits
- compress and store as `webp`
- return metadata so the frontend can warn the user

Images that are too small or have an extreme aspect ratio are still rejected.

### Response Metadata

The response includes:

- `back_image_original_size_bytes`
- `back_image_size_bytes`
- `back_image_was_optimized`
- `back_image_width`
- `back_image_height`
- `backImageWarnings`
- `backImageRenderHint`
- `image_constraints`

Common render hints:

- `text_only`
- `image_top_text_bottom`
- `optimized_image`
- `wide_image`
- `tall_image`
- `small_text_space`

### cURL Example

```bash
curl -X POST "http://127.0.0.1:8000/api/decks/50/add-rich-card/" \
  -H "Authorization: Token YOUR_TOKEN" \
  -F "front=What does this image show?" \
  -F "back=This text appears below the image on the back side." \
  -F "notes=teacher note" \
  -F "back_image=@C:/path/to/image.png"
```

### Example Success Response

```json
{
  "deck_id": 50,
  "job_id": "76335464-721b-43e6-b890-bb04f4436df7",
  "image_constraints": {
    "allowed_formats": ["jpg", "png", "webp"],
    "max_file_size_bytes": 3145728,
    "max_file_size_mb": 3.0,
    "min_resolution": { "width": 400, "height": 400 },
    "max_resolution": { "width": 2000, "height": 2000 },
    "max_aspect_ratio": 3.0,
    "auto_optimize_when_needed": true,
    "optimized_storage_format": "webp"
  },
  "card": {
    "id": 225,
    "front": "What does this image show?",
    "back": "This text appears below the image on the back side.",
    "backImageUrl": "uploaded image url",
    "back_image_original_size_bytes": 25276,
    "back_image_size_bytes": 7198,
    "back_image_was_optimized": true,
    "back_image_width": 2000,
    "back_image_height": 2000,
    "backImageWarnings": [
      "This image was automatically optimized to fit the flashcard limits."
    ],
    "backImageRenderHint": "optimized_image"
  }
}
```

---

## 1.2) Rich Card Upload Config

Endpoint:

- `GET /api/decks/rich-card-config/`

### Purpose

Lets the frontend load the upload constraints and render guidance before the user selects or submits an image.

### Response Includes

- `image_constraints`
- `render_guidance.default_layout`
- `render_guidance.image_fit`
- `render_guidance.max_preview_height_px`
- `render_guidance.warnings`

### Frontend Use

Recommended UI behavior:

- show local image size and resolution before upload
- show backend constraints in the form
- show backend warning messages after upload
- render image with `object-fit: contain`
- render explanation text below the image

### cURL Example

```bash
curl -X GET "http://127.0.0.1:8000/api/decks/rich-card-config/" \
  -H "Authorization: Token YOUR_TOKEN"
```

---

## 2) Download Questions PDF (Exam Format)

Endpoint:

- `GET /api/batteries/{battery_id}/download-questions-pdf/`

### Query Parameters

- `disposition` (optional): `attachment` or `inline`
  - Default: `attachment`
  - `attachment`: forces file download
  - `inline`: opens PDF in browser viewer/tab when possible

### What this PDF includes

- Enumerated questions
- `Type`
- `Items` (options) in exam style
- Separate answers section:
  - `Answer` (enumerated if multiple)
  - `Hint`
  - `Where to Check` (page/document reference when available)

### cURL Examples

```bash
# EN
curl -X GET "http://127.0.0.1:8000/api/batteries/16/download-questions-pdf/?disposition=attachment" \
  -H "Authorization: Token YOUR_TOKEN" \
  -H "language: en" \
  -o battery_16_en.pdf
```

```bash
# ES
curl -X GET "http://127.0.0.1:8000/api/batteries/16/download-questions-pdf/?disposition=attachment" \
  -H "Authorization: Token YOUR_TOKEN" \
  -H "language: es" \
  -o battery_16_es.pdf
```

### Frontend (fetch) Example

```js
async function downloadQuestionsPdf(batteryId, token, language = "en") {
  const url = `/api/batteries/${batteryId}/download-questions-pdf/?disposition=attachment`;
  const res = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Token ${token}`,
      language,
    },
  });

  if (!res.ok) throw new Error(`Download failed: ${res.status}`);

  const blob = await res.blob();
  const contentDisposition = res.headers.get("Content-Disposition") || "";
  const match = contentDisposition.match(/filename\\*?=(?:UTF-8''|")?([^\";]+)/i);
  const filename = match ? decodeURIComponent(match[1].replace(/"/g, "")) : `battery_${batteryId}_${language}.pdf`;

  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}
```

---

## Response Headers (Client Useful)

Flashcards endpoint exposes:

- `Content-Disposition`
- `X-Print-Mode-Applied`
- `X-Duplex-Flip-Applied`

Questions endpoint exposes:

- `Content-Disposition`

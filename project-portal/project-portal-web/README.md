
# Project Portal Web: Developer Onboarding & Monitoring UI

![Next.js 15](https://img.shields.io/badge/Next.js-15-black)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue)
![Tailwind CSS](https://img.shields.io/badge/TailwindCSS-3.4-cyan)
![Stellar Mainnet](https://img.shields.io/badge/Stellar-Mainnet-red)
![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-green)

The **Project Portal Web** is the developer-facing frontend for onboarding, monitoring, and financing carbon projects on CarbonScribe. It provides interactive dashboards, project mapping, and seamless integration with the backend and Stellar blockchain.

---

## 📚 Table of Contents
- [Overview](#-overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [API Integration](#api-integration)
- [Contributing](#contributing)

---

## 🌱 Overview
Project Portal Web enables:
- Project onboarding with AI-assisted forms
- Real-time NDVI and satellite monitoring
- Forward sale and tokenization workflows
- Developer dashboards and analytics

## ✨ Features
- Interactive project mapping (Mapbox, TimeLapse)
- NDVI timelines and alert dashboards
- Financing and tokenization wizards
- Role-based access and secure authentication
- Responsive UI with dark/light mode

## 🛠️ Tech Stack
- **Next.js 15** (App Router)
- **TypeScript**
- **Tailwind CSS**
- **Recharts** (data visualization)
- **Zustand** (state management)
- **React Hook Form** + **Zod** (forms & validation)

## 📁 Project Structure

```
src/
├── app/
│   ├── (auth)/
│   ├── (portal)/
│   ├── api/
│   ├── favicon.ico
│   ├── globals.css
│   └── layout.tsx
├── components/
│   ├── AuthNavigation.tsx
│   ├── PortalNavbar.tsx
│   ├── PortalSidebar.tsx
│   ├── ProtectedRoute.tsx
│   ├── StoreHydrator.tsx
│   ├── actions/
│   ├── collaboration/
│   ├── dashboard/
│   ├── financing/
│   ├── insights/
│   ├── integrations/
│   ├── maps/
│   ├── monitoring/
│   ├── projects/
│   ├── reports/
│   └── ui/
├── contexts/
│   └── FarmerContext.tsx
├── lib/
│   ├── api/
│   ├── api.ts
│   ├── auth.ts
│   ├── geospatial/
│   ├── ipfs/
│   ├── stellar/
│   ├── store/
│   └── utils/
├── store/
│   ├── integration.api.ts
│   ├── integration.selectors.ts
│   ├── integration.types.ts
│   ├── integrationSlice.ts
│   ├── reports.api.ts
│   ├── reports.selectors.ts
│   ├── reports.types.ts
│   ├── reportsSlice.ts
│   └── store.ts
├── test/
│   └── setup.ts
```

---

## ⚡ Quick Start
1. Install dependencies:
	```bash
	npm install
	# or
yarn
	```
2. Copy `.env.example` to `.env.local` and set API URLs as needed.
3. Run the development server:
	```bash
	npm run dev
	# or
yarn dev
	```
4. Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🔗 API Integration
- Set `NEXT_PUBLIC_REPORTS_API_URL` in `.env.local` to point to your backend.
- Ensure [project-portal-backend](../project-portal-backend) is running for full functionality.

---

## 🤝 Contributing
Pull requests welcome! See root CONTRIBUTING.md for guidelines.

---

*Part of the CarbonScribe 7-Layer Architecture. See project-portal/README.md for full context.*

# CarbonScribe Corporate Platform

A modern Next.js web application for corporate buyers to purchase, manage, and retire carbon credits with transparent, on-chain verification.

## Features

- **Dashboard Overview**: Real-time portfolio metrics and performance analytics
- **Credit Marketplace**: Browse and purchase verified carbon credits
- **Instant Retirement**: Retire credits with on-chain verification
- **Portfolio Analytics**: Visual breakdown by methodology and region
- **Live Retirement Feed**: Real-time updates on corporate retirements
- **Compliance Reporting**: Generate ESG and sustainability reports
- **Dark/Light Mode**: Full theme support
- **Mobile Responsive**: Optimized for all device sizes

## Tech Stack

- **Next.js 15** - React framework with App Router
- **TypeScript** - Type safety
- **Tailwind CSS** - Utility-first styling
- **Recharts** - Data visualization
- **Lucide React** - Icon library
- **Next Themes** - Dark/light mode
- **Zustand** - State management
- **React Hook Form** - Form handling
- **Zod** - Schema validation

## Project Structure


```
src/
├── app/
│   ├── analytics/
│   ├── api/
│   ├── compliance/
│   ├── corporate/
│   ├── favicon.ico
│   ├── globals.css
│   ├── layout.tsx
│   ├── marketplace/
│   ├── page.tsx
│   ├── portfolio/
│   ├── projects/
│   ├── reporting/
│   ├── retirement/
│   ├── settings/
│   └── team/
├── components/
│   ├── actions/
│   ├── analytics/
│   ├── dashboard/
│   ├── feed/
│   ├── goals/
│   ├── layout/
│   ├── marketplace/
│   ├── reporting/
│   ├── retirement/
│   └── theme/
├── contexts/
│   └── CorporateContext.tsx
├── hooks/
│   └── useTheme.ts
├── lib/
│   ├── analytics/
│   ├── compliance/
│   └── mockData.ts
├── types/
│   └── index.ts
```

---
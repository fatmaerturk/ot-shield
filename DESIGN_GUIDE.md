# OTShield Modern Design Guide

## 🎨 Color Palette

| Color | Usage | Code |
|-------|-------|------|
| **Blue (Primary)** | Main actions, headers | `#3b82f6` |
| **Purple (Secondary)** | Accents, highlights | `#8b5cf6` |
| **Green (Success)** | Positive states, confirmations | `#10b981` |
| **Orange (Warning)** | Warnings, alerts | `#f59e0b` |
| **Red (Danger)** | Critical errors, threats | `#ef4444` |
| **Gray-50 (Background)** | Page background | `#f9fafb` |
| **White (Surface)** | Cards, containers | `#ffffff` |

## 📐 Component Guidelines

### Cards
```html
<!-- Modern card with border accent -->
<div class="bg-white rounded-lg shadow-sm hover:shadow-md transition-all duration-200 p-6 border-l-4 border-l-blue-500">
  <!-- content -->
</div>
```

### Buttons
```html
<!-- Primary button -->
<button class="bg-blue-500 text-white hover:bg-blue-600 px-4 py-2 rounded-lg font-medium transition-colors">
  Action
</button>

<!-- Secondary button -->
<button class="bg-gray-200 text-gray-900 hover:bg-gray-300 px-4 py-2 rounded-lg font-medium transition-colors">
  Secondary
</button>
```

### Badges
```html
<!-- Success badge -->
<span class="inline-block bg-green-100 text-green-700 px-3 py-1 rounded-full text-sm font-medium">
  Success
</span>

<!-- Warning badge -->
<span class="inline-block bg-yellow-100 text-yellow-700 px-3 py-1 rounded-full text-sm font-medium">
  Warning
</span>

<!-- Critical badge -->
<span class="inline-block bg-red-100 text-red-700 px-3 py-1 rounded-full text-sm font-medium">
  Critical
</span>
```

### Input Fields
```html
<input 
  class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-colors"
  type="text"
/>
```

### Progress Bars
```html
<div class="h-2 bg-gray-200 rounded-full overflow-hidden">
  <div class="h-full bg-blue-500" style="width: 65%"></div>
</div>
```

## 🎯 Layout Standards

### Page Structure
```
Header (Fixed Navigation)
  ↓
Main Content (max-width: 7xl)
  ↓
Footer
```

### Navigation
- Fixed top bar with blue bottom border
- Logo on left, menu items in center, user profile on right
- Responsive hamburger menu on mobile

### Spacing
- **Page padding**: 32px (8 units)
- **Card padding**: 24px (6 units)
- **Element gaps**: 16px (4 units)

## 📱 Responsive Design

| Screen | Width |
|--------|-------|
| Mobile | < 768px |
| Tablet | 768px - 1024px |
| Desktop | > 1024px |

Use Tailwind's responsive prefixes:
- `sm:` (640px)
- `md:` (768px)
- `lg:` (1024px)
- `xl:` (1280px)

## 🔤 Typography

| Level | Size | Weight | Usage |
|-------|------|--------|-------|
| H1 | 32px | 700 | Page titles |
| H2 | 28px | 700 | Section headers |
| H3 | 20px | 600 | Card titles |
| Body | 16px | 400 | Normal text |
| Small | 14px | 400 | Labels |
| Tiny | 12px | 400 | Metadata |

## ✨ Effects & Transitions

### Hover States
```css
/* Cards */
hover:shadow-md hover:-translate-y-0.5

/* Buttons */
hover:bg-blue-600

/* Links */
hover:text-blue-600
```

### Transitions
- Duration: 200ms for hover effects
- Easing: ease-in-out
- Properties: colors, shadows, transforms

## 🚀 Best Practices

1. **Consistency**: Use the defined color palette across all pages
2. **Spacing**: Maintain consistent gaps between elements (use 4px grid)
3. **Shadows**: Use subtle shadows (sm or md) for depth
4. **Borders**: Use border-l-4 for card accents
5. **Icons**: Use emoji for quick visual indicators
6. **Animations**: Keep animations subtle and fast (200-300ms)
7. **Accessibility**: Ensure sufficient color contrast, use semantic HTML
8. **Mobile-first**: Design mobile layout first, then scale up

## 📦 Component Library

### ModernCard Component
```tsx
<ModernCard 
  title="Dashboard"
  icon="📊"
  borderColor="blue"
>
  {/* content */}
</ModernCard>
```

### Usage in Pages
- All metric cards → ModernCard with blue/purple borders
- Alert cards → ModernCard with red borders
- Success cards → ModernCard with green borders

## 🎬 Implementation Checklist

- [ ] Replace all cards with ModernCard component
- [ ] Update button styles to use consistent colors
- [ ] Add hover effects to interactive elements
- [ ] Update badge styles for alerts
- [ ] Improve responsive design on mobile
- [ ] Add smooth transitions between pages
- [ ] Update footer styling
- [ ] Test on different screen sizes

## 📚 Resources

- Tailwind CSS: https://tailwindcss.com
- Color palette: Use colors defined above
- Icons: Use emoji or Heroicons
- Animations: Framer Motion

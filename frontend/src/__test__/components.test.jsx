/**
 * Component render tests.
 *
 * The existing suite asserted only on the API client's exported shape,
 * because nothing could render: jest, babel-jest and @babel/preset-react
 * were installed but there was no Babel config, so any test importing
 * application code failed with "Cannot use import statement outside a
 * module". With that fixed and @testing-library/react added, components can
 * actually be exercised.
 *
 * Deliberately focused on behaviour a reviewer would care about — that a
 * component renders its data, and that the planted XSS is still reachable —
 * rather than snapshotting markup, which breaks on every styling change and
 * asserts nothing about correctness.
 */

import { render, screen } from '@testing-library/react'
import '@testing-library/jest-dom'
import { MemoryRouter } from 'react-router-dom'

import ProductCard from '../components/ProductCard'
import ReviewList from '../components/ReviewList'

const product = {
  id: 1,
  name: 'Mechanical Keyboard',
  description: 'Clicky and loud',
  price: 129.99,
  category: 'peripherals',
  image_url: '/images/keyboard.jpg',
  stock: 7,
}

describe('ProductCard', () => {
  const renderCard = (p = product) =>
    render(
      <MemoryRouter>
        <ProductCard product={p} />
      </MemoryRouter>
    )

  test('renders the product name and price', () => {
    renderCard()
    expect(screen.getByText('Mechanical Keyboard')).toBeInTheDocument()
    expect(screen.getByText(/129\.99/)).toBeInTheDocument()
  })

  test('renders without crashing when optional fields are missing', () => {
    // Product data comes straight from the API, and products.search builds
    // its rows by hand from a raw SQL result — a null description or
    // image_url is a realistic shape, not a hypothetical one.
    expect(() =>
      renderCard({ ...product, description: null, image_url: null })
    ).not.toThrow()
  })
})

describe('ReviewList', () => {
  const reviews = [
    { id: 1, rating: 5, comment: 'Excellent build quality', username: 'alice' },
    { id: 2, rating: 2, comment: '<img src=x onerror="alert(1)">', username: 'mallory' },
  ]

  test('renders every review', () => {
    render(<ReviewList reviews={reviews} />)
    expect(screen.getByText(/Excellent build quality/)).toBeInTheDocument()
  })

  test('VULN (intentional): review comments are still rendered as raw HTML', () => {
    // README documents ReviewList's dangerouslySetInnerHTML as the stored
    // XSS example, and CodeQL/SonarCloud report it every run. If someone
    // "fixes" it by escaping, the app gets safer and the security pipeline
    // silently loses a finding the demo depends on — so assert the sink is
    // still there, the same guard the backend suite applies to the SQLi
    // route.
    const { container } = render(<ReviewList reviews={reviews} />)
    const injected = container.querySelector('img[onerror]')
    expect(injected).not.toBeNull()
  })
})

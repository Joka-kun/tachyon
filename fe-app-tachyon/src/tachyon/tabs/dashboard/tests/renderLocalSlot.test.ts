import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render } from '../render';

const getLayout = vi.hoisted(() => vi.fn());

vi.mock('../dashboardLayout', () => ({
  getDashboardLayoutConfig: getLayout,
  computeAutoFullWidgetIds: () => new Set<string>(),
}));

vi.mock('../partials', () => ({
  renderSections: () => [],
  renderWidget: () => null,
}));

interface FixtureNode {
  tag: string;
  attrs: Record<string, unknown>;
  children: unknown[];
}

describe('Independent TorrServer dashboard slot', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'E',
      (tag: string, attrs: Record<string, unknown>, children: unknown = []) => ({
        tag,
        attrs,
        children: Array.isArray(children) ? children : [children],
      }),
    );
  });

  afterEach(() => {
    getLayout.mockReset();
    vi.unstubAllGlobals();
  });

  it.each([
    { name: 'absent inbound placement', widgets: [] },
    {
      name: 'visible full-width inbounds',
      widgets: [{ id: 'inbounds', enabled: true, width: 'full', view: 'default' }],
    },
    {
      name: 'hidden inbounds',
      widgets: [{ id: 'inbounds', enabled: false, width: 'full', view: 'default' }],
    },
    {
      name: 'compact half-width inbounds',
      widgets: [{ id: 'inbounds', enabled: true, width: 'half', view: 'compact' }],
    },
    {
      name: 'matrix half-width inbounds',
      widgets: [{ id: 'inbounds', enabled: true, width: 'half', view: 'matrix' }],
    },
  ])('renders one independent local service slot: $name', ({ widgets }) => {
    getLayout.mockReturnValue({ preset: 'custom', widgets });
    const root = render() as unknown as FixtureNode;
    const content = root.children[0] as FixtureNode;
    const slots = content.children as FixtureNode[];
    const localSlots = slots.filter(
      (slot) => slot.attrs.id === 'dashboard-widget-torrserver',
    );

    expect(localSlots).toHaveLength(1);
    expect(
      slots.filter((slot) => slot.attrs.id === 'dashboard-widget-inbounds'),
    ).toHaveLength(1);

    const localSlot = localSlots[0];
    expect(localSlot.attrs.class).toContain(
      'tachyon-dashboard-widget-slot--full',
    );
    expect(localSlot.attrs.class).not.toContain(
      'tachyon-dashboard-widget-slot--hidden',
    );
    expect(localSlot.attrs['data-widget-id']).toBeUndefined();
    expect(localSlot.attrs.style).toContain('display:none');
    expect(localSlot.children).toHaveLength(1);
    const grid = localSlot.children[0] as FixtureNode;
    expect(grid.attrs.id).toBe('dashboard-torrserver-grid');
    expect(grid.attrs.class).toBe('tachyon-inbounds-chip-grid');
  });
});

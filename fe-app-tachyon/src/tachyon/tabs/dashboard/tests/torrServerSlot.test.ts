import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render } from '../render';

const getDashboardLayoutConfig = vi.hoisted(() => vi.fn());

vi.mock('../dashboardLayout', () => ({
  getDashboardLayoutConfig,
  computeAutoFullWidgetIds: () => new Set(),
}));

vi.mock('../partials', () => ({
  renderSections: () => [],
  renderWidget: () => ({ attrs: {}, children: [] }),
}));

interface TestNode {
  attrs: Record<string, string>;
  children: TestNode[];
}

function findById(node: TestNode, id: string): TestNode[] {
  return [
    ...(node.attrs.id === id ? [node] : []),
    ...node.children.flatMap((child) => findById(child, id)),
  ];
}

describe('independent TorrServer dashboard slot', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'E',
      (
        _tag: string,
        attrs: Record<string, string>,
        children: TestNode | TestNode[] | string = [],
      ): TestNode => ({
        attrs,
        children: (Array.isArray(children) ? children : [children]).filter(
          (child): child is TestNode => typeof child === 'object',
        ),
      }),
    );
    vi.stubGlobal('_', (text: string) => text);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    getDashboardLayoutConfig.mockReset();
  });

  it.each([
    'standard',
    'command_center',
    'noc_analytics',
    'bento_cards',
    'minimal_zen',
    'custom',
  ])('keeps a unique independent slot in %s', (preset) => {
    getDashboardLayoutConfig.mockReturnValue({
      preset,
      widgets: [
        { id: 'inbounds', enabled: false, width: 'half', view: 'default' },
      ],
    });
    const root = render() as unknown as TestNode;
    const inbound = findById(root, 'dashboard-widget-inbounds');
    const slots = findById(root, 'dashboard-widget-torrserver');
    expect(inbound).toHaveLength(1);
    expect(inbound[0].attrs.style).toContain('display: none');
    expect(slots).toHaveLength(1);
    expect(slots[0].attrs.class).toContain('tachyon-dashboard-widget-slot--full');
    expect(slots[0].attrs.style).toContain('display:none');
    expect(slots[0].attrs.class).not.toContain(
      'tachyon-dashboard-widget-slot--hidden',
    );
    expect(slots[0].attrs['data-widget-id']).toBeUndefined();
    const grids = findById(slots[0], 'dashboard-torrserver-grid');
    expect(grids).toHaveLength(1);
    expect(grids[0].attrs.class).toBe('tachyon-inbounds-chip-grid');
    expect(findById(inbound[0], 'dashboard-torrserver-grid')).toHaveLength(0);
  });

  it.each([
    { width: 'full', view: 'default' },
    { width: 'half', view: 'compact' },
    { width: 'half', view: 'matrix' },
  ])('keeps the slot independent of visible $width/$view inbounds', (mode) => {
    getDashboardLayoutConfig.mockReturnValue({
      preset: 'custom',
      widgets: [{ id: 'inbounds', enabled: true, ...mode }],
    });
    const root = render() as unknown as TestNode;
    const inbound = findById(root, 'dashboard-widget-inbounds');
    const slots = findById(root, 'dashboard-widget-torrserver');
    expect(inbound).toHaveLength(1);
    expect(inbound[0].attrs.style).not.toContain('display: none');
    expect(slots).toHaveLength(1);
    expect(slots[0].attrs.class).toContain('tachyon-dashboard-widget-slot--full');
    expect(slots[0].attrs['data-widget-id']).toBeUndefined();
    expect(slots[0].attrs.style).toContain('display:none');
    expect(findById(root, 'dashboard-torrserver-grid')).toHaveLength(1);
    expect(findById(inbound[0], 'dashboard-torrserver-grid')).toHaveLength(0);
  });

  it('keeps the optional slot when there is no inbound placement', () => {
    getDashboardLayoutConfig.mockReturnValue({
      preset: 'custom',
      widgets: [],
    });
    const root = render() as unknown as TestNode;
    expect(findById(root, 'dashboard-widget-torrserver')).toHaveLength(1);
    expect(findById(root, 'dashboard-torrserver-grid')).toHaveLength(1);
  });
});

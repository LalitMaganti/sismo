// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

// Sismo's home page. Drop-in overlay for perfetto's
// ui/src/frontend/home_page.ts — same exported class name (`HomePage`)
// and same shape (Quick start, Shortcuts, Channel select), rebranded
// title to 'Sismo', and the Google docs/privacy links replaced with a
// sismo-on-GitHub link.
//
// Why this lives as an overlay (vs SismoEmbedder.homePage = SismoHomePage):
// importing the class from sismo_embedder pulls in AppImpl, which pulls
// in createEmbedder, which pulls in external_embedder, which pulls in
// sismo_embedder — a cycle. Replacing home_page.ts directly side-steps
// the cycle: frontend/index.ts already imports HomePage as the default,
// no embedder reference required.

import m from 'mithril';
import {
  channelChanged,
  getCurrentChannel,
  getNextChannel,
  setChannel,
} from '../core/channels';
import {AppImpl} from '../core/app_impl';
import {Anchor} from '../widgets/anchor';
import {Button, ButtonVariant} from '../widgets/button';
import {Intent} from '../widgets/common';
import {HotkeyGlyphs, Keycap} from '../widgets/hotkey_glyphs';
import {Switch} from '../widgets/switch';
import {Stack} from '../widgets/stack';
import {Icons} from '../base/semantic_icons';
import {Icon} from '../widgets/icon';
import {classNames} from '../base/classnames';
import {Router} from '../core/router';
import {
  KeyboardLayoutMap,
  nativeKeyboardLayoutMap,
  NotSupportedError,
} from '../base/keyboard_layout_map';
import {Spinner} from '../widgets/spinner';
import {KeyMapping} from '../base/wasd_key_mapping';

export class HomePage implements m.ClassComponent {
  view() {
    return m(
      '.pf-home-page',
      m(
        '.pf-home-page__center',
        m('.pf-home-page__title', 'Sismo'),
        m(Hints),
        m(ChannelSelect),
      ),
    );
  }
}

class ChannelSelect implements m.ClassComponent {
  view() {
    const showAutopush = getCurrentChannel() === 'autopush';
    const channels = showAutopush
      ? ['stable', 'canary', 'autopush']
      : ['stable', 'canary'];

    return m(
      `.pf-channel-select`,
      {
        className: classNames(
          showAutopush && 'pf-channel-select--with-autopush',
        ),
      },
      m(
        '.pf-channel-select__text',
        'Feeling adventurous? Try our bleeding edge Canary version.',
      ),
      m(
        'fieldset.pf-channel-select__switch',
        ...channels.map((channel) => {
          const checked = getNextChannel() === channel ? '[checked=true]' : '';
          return [
            m(`input[type=radio][name=chan][id=chan_${channel}]${checked}`, {
              onchange: () => {
                setChannel(channel);
              },
            }),
            m(`label[for=chan_${channel}]`, channel),
          ];
        }),
        m('.pf-channel-select__pill'),
      ),
      m(
        '.pf-channel-select__reload-hint',
        {
          className: classNames(
            channelChanged() && 'pf-channel-select__reload-hint--visible',
          ),
        },
        m(
          '.pf-channel-select__reload-hint-text',
          'You need to reload the page for the changes to have effect',
        ),
        m(Button, {
          label: 'Reload',
          icon: 'refresh',
          variant: ButtonVariant.Filled,
          intent: Intent.Danger,
          onclick: () => window.location.reload(),
        }),
      ),
    );
  }
}

// Fallback keyboard map for environments where nativeKeyboardLayoutMap is
// unavailable; converts 'KeyX' codes to their QWERTY glyphs.
class EnglishQwertyKeyboardLayoutMap implements KeyboardLayoutMap {
  get(code: string): string {
    return code.replace(/^Key([A-Z])$/, '$1').toLowerCase();
  }
}

class Hints implements m.ClassComponent {
  private keyMap?: KeyboardLayoutMap;

  oninit() {
    nativeKeyboardLayoutMap()
      .then((keyMap: KeyboardLayoutMap) => {
        this.keyMap = keyMap;
        m.redraw();
      })
      .catch((e) => {
        if (
          e instanceof NotSupportedError ||
          String(e).includes('SecurityError')
        ) {
          this.keyMap = new EnglishQwertyKeyboardLayoutMap();
          m.redraw();
        } else {
          throw e;
        }
      });
  }

  private codeToKeycap(code: string): m.Children {
    if (this.keyMap) {
      return m(Keycap, this.keyMap.get(code)?.toUpperCase());
    } else {
      return m(Keycap, m(Spinner));
    }
  }

  view() {
    const themeSetting = AppImpl.instance.settings.get<string>('theme');
    const isDarkMode = themeSetting?.get() === 'dark';

    return m(
      '.pf-home-page__hints',
      m(
        '.pf-home-page__section',
        m('.pf-home-page__section-title', 'Quick start'),
        m(
          '.pf-home-page__section-content',
          m(
            '.pf-home-page__getting-started-buttons',
            m(
              '.pf-home-page__button',
              {
                onclick: () => {
                  AppImpl.instance.commands.runCommand(
                    'dev.perfetto.OpenTrace',
                  );
                },
              },
              m(Icon, {icon: 'folder_open', className: 'pf-left-icon'}),
              m('span.pf-button__label', 'Open trace'),
            ),
            m(
              '.pf-home-page__button',
              {
                onclick: () => {
                  Router.navigate('#!/record');
                },
              },
              m(Icon, {icon: 'fiber_smart_record', className: 'pf-left-icon'}),
              m('span.pf-button__label', 'Record new trace'),
            ),
          ),
        ),
      ),
      m(
        '.pf-home-page__section',
        m('.pf-home-page__section-title', 'Shortcuts'),
        m(
          '.pf-home-page__section-content',
          m(
            '.pf-home-page__shortcut',
            m('span.pf-home-page__shortcut-label', 'Find tracks'),
            m(HotkeyGlyphs, {hotkey: 'Mod+P'}),
          ),
          m(
            '.pf-home-page__shortcut',
            m('span.pf-home-page__shortcut-label', 'Navigate timeline'),
            m(
              Stack,
              {inline: true, spacing: 'small', orientation: 'horizontal'},
              [
                this.codeToKeycap(KeyMapping.KEY_ZOOM_IN),
                this.codeToKeycap(KeyMapping.KEY_PAN_LEFT),
                this.codeToKeycap(KeyMapping.KEY_ZOOM_OUT),
                this.codeToKeycap(KeyMapping.KEY_PAN_RIGHT),
              ],
            ),
          ),
          m(
            '.pf-home-page__shortcut',
            m('span.pf-home-page__shortcut-label', 'Commands'),
            m(HotkeyGlyphs, {hotkey: '!Mod+Shift+P'}),
          ),
        ),
      ),
      m(
        '.pf-home-page__links',
        m(
          Anchor,
          {
            href: 'https://github.com/LalitMaganti/sismo',
            icon: Icons.ExternalLink,
            target: '_blank',
          },
          'sismo on GitHub',
        ),
        m('.pf-home-page__links-separator'),
        m(Switch, {
          label: 'Dark mode',
          checked: isDarkMode,
          onchange: (e) => {
            themeSetting?.set(
              (e.target as HTMLInputElement).checked ? 'dark' : 'light',
            );
          },
        }),
      ),
    );
  }
}

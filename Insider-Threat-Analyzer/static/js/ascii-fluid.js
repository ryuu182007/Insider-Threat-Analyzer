/**
 * ASCII fluid background - vanilla JS (no React / Tailwind / TypeScript needed).
 * Port of the "ascii-fluid" React component: pointer trails leave ink that swirls
 * and is quantised to a brightness-mapped glyph field. WebGL 1, zero dependencies.
 *
 *   const fx = createAsciiFluid(canvas, { color: '#B5223E', backgroundColor: '#080607' });
 *   fx.setOptions({ color: '#8F1830', backgroundColor: '#f7f3f5' });
 *   fx.destroy();
 */
(function () {
    'use strict';

    var DEFAULT_CHARSET = " .'`^\",:;Il!i><~+_-?][}{1)(|\\/tfjrxnuvczXYUJCLQ0OZmwqpdbkhao*#MW&8%B@$";
    var LIGHT = { ink: '#18181b', paper: '#fafafa' };
    var DARK = { ink: '#e4e4e7', paper: '#09090b' };

    var VERT = [
        'attribute vec2 a_position;',
        'varying vec2 v_uv;',
        'void main() { v_uv = a_position * 0.5 + 0.5; gl_Position = vec4(a_position, 0.0, 1.0); }'
    ].join('\n');

    var ENC = [
        'vec2 dec(vec2 e) { return (e - 0.5) / 0.05; }',
        'vec2 enc(vec2 v) { return clamp(v * 0.05 + 0.5, 0.0, 1.0); }',
        'float dec1(float e) { return (e - 0.5) / 0.05; }',
        'float enc1(float v) { return clamp(v * 0.05 + 0.5, 0.0, 1.0); }'
    ].join('\n');

    var FRAG_SPLAT = 'precision highp float;\nvarying vec2 v_uv;\n' + ENC + '\n' + [
        'uniform sampler2D u_target; uniform vec2 u_point; uniform vec3 u_color;',
        'uniform float u_radius; uniform float u_aspect; uniform float u_velocityField;',
        'void main() {',
        '  vec2 p = v_uv - u_point; p.x *= u_aspect;',
        '  float d = exp(-dot(p, p) / max(u_radius, 0.0001));',
        '  vec3 base = texture2D(u_target, v_uv).xyz;',
        '  if (u_velocityField > 0.5) {',
        '    vec2 next = dec(base.xy) + u_color.xy * d;',
        '    gl_FragColor = vec4(enc(next), 0.5, 1.0);',
        '  } else { gl_FragColor = vec4(base + u_color * d, 1.0); }',
        '}'
    ].join('\n');

    var FRAG_ADVECT = 'precision highp float;\nvarying vec2 v_uv;\n' + ENC + '\n' + [
        'uniform sampler2D u_velocity; uniform sampler2D u_source; uniform vec2 u_texel;',
        'uniform float u_dt; uniform float u_dissipation; uniform float u_velocityField;',
        'void main() {',
        '  vec2 vel = dec(texture2D(u_velocity, v_uv).xy);',
        '  vec2 coord = v_uv - u_dt * vel * u_texel * 110.0;',
        '  vec4 src = texture2D(u_source, clamp(coord, 0.0, 1.0));',
        '  if (u_velocityField > 0.5) {',
        '    vec2 next = dec(src.xy) * u_dissipation;',
        '    gl_FragColor = vec4(enc(next), 0.5, 1.0);',
        '  } else { gl_FragColor = vec4(src.xyz * u_dissipation, 1.0); }',
        '}'
    ].join('\n');

    var FRAG_DIVERGENCE = 'precision highp float;\nvarying vec2 v_uv;\n' + ENC + '\n' + [
        'uniform sampler2D u_velocity; uniform vec2 u_texel;',
        'void main() {',
        '  float L = dec(texture2D(u_velocity, v_uv - vec2(u_texel.x, 0.0)).xy).x;',
        '  float R = dec(texture2D(u_velocity, v_uv + vec2(u_texel.x, 0.0)).xy).x;',
        '  float B = dec(texture2D(u_velocity, v_uv - vec2(0.0, u_texel.y)).xy).y;',
        '  float T = dec(texture2D(u_velocity, v_uv + vec2(0.0, u_texel.y)).xy).y;',
        '  float div = 0.5 * ((R - L) + (T - B));',
        '  gl_FragColor = vec4(div * 0.05 + 0.5, 0.0, 0.0, 1.0);',
        '}'
    ].join('\n');

    var FRAG_PRESSURE = 'precision highp float;\nvarying vec2 v_uv;\n' + ENC + '\n' + [
        'uniform sampler2D u_pressure; uniform sampler2D u_divergence; uniform vec2 u_texel;',
        'void main() {',
        '  float L = dec1(texture2D(u_pressure, v_uv - vec2(u_texel.x, 0.0)).x);',
        '  float R = dec1(texture2D(u_pressure, v_uv + vec2(u_texel.x, 0.0)).x);',
        '  float B = dec1(texture2D(u_pressure, v_uv - vec2(0.0, u_texel.y)).x);',
        '  float T = dec1(texture2D(u_pressure, v_uv + vec2(0.0, u_texel.y)).x);',
        '  float C = dec1(texture2D(u_divergence, v_uv).x);',
        '  float p = (L + R + B + T - C) * 0.25;',
        '  gl_FragColor = vec4(enc1(p), 0.0, 0.0, 1.0);',
        '}'
    ].join('\n');

    var FRAG_GRADIENT = 'precision highp float;\nvarying vec2 v_uv;\n' + ENC + '\n' + [
        'uniform sampler2D u_pressure; uniform sampler2D u_velocity; uniform vec2 u_texel;',
        'void main() {',
        '  float L = dec1(texture2D(u_pressure, v_uv - vec2(u_texel.x, 0.0)).x);',
        '  float R = dec1(texture2D(u_pressure, v_uv + vec2(u_texel.x, 0.0)).x);',
        '  float B = dec1(texture2D(u_pressure, v_uv - vec2(0.0, u_texel.y)).x);',
        '  float T = dec1(texture2D(u_pressure, v_uv + vec2(0.0, u_texel.y)).x);',
        '  vec2 vel = dec(texture2D(u_velocity, v_uv).xy);',
        '  vel -= vec2(R - L, T - B) * 0.5;',
        '  gl_FragColor = vec4(enc(vel), 0.5, 1.0);',
        '}'
    ].join('\n');

    var FRAG_DISPLAY = [
        'precision highp float;',
        'varying vec2 v_uv;',
        'uniform sampler2D u_dye; uniform sampler2D u_atlas;',
        'uniform vec2 u_resolution; uniform vec2 u_cell; uniform float u_charCount;',
        'uniform vec3 u_ink; uniform vec3 u_paper; uniform float u_time; uniform float u_animate;',
        'float hash21(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }',
        'void main() {',
        '  vec2 pixel = v_uv * u_resolution;',
        '  vec2 cell = floor(pixel / u_cell);',
        '  vec2 cellUv = (cell + 0.5) * u_cell / u_resolution;',
        '  float dens = clamp(texture2D(u_dye, cellUv).x, 0.0, 1.0);',
        '  vec2 texel = u_cell / u_resolution;',
        '  float glow = dens * 0.40',
        '    + texture2D(u_dye, cellUv + vec2( texel.x, 0.0)).x * 0.15',
        '    + texture2D(u_dye, cellUv - vec2( texel.x, 0.0)).x * 0.15',
        '    + texture2D(u_dye, cellUv + vec2(0.0,  texel.y)).x * 0.15',
        '    + texture2D(u_dye, cellUv - vec2(0.0,  texel.y)).x * 0.15;',
        '  glow = pow(clamp(glow, 0.0, 1.0), 1.35);',
        '  float lit = dens;',
        '  if (u_animate > 0.5) {',
        '    float flicker = hash21(cell + floor(u_time * 10.0)) - 0.5;',
        '    lit = clamp(lit + flicker * 0.05, 0.0, 1.0);',
        '  }',
        '  float idx = min(floor(lit * (u_charCount - 0.001)), u_charCount - 1.0);',
        '  vec2 local = fract(pixel / u_cell);',
        '  float u0 = (idx + local.x) / u_charCount;',
        '  float glyph = texture2D(u_atlas, vec2(u0, local.y)).r;',
        '  float alpha = glyph * smoothstep(0.02, 0.12, dens);',
        '  float wash = glow * 0.22;',
        '  vec3 col = mix(u_paper, u_ink, wash);',
        '  col = mix(col, u_ink, clamp(alpha, 0.0, 1.0));',
        '  gl_FragColor = vec4(col, 1.0);',
        '}'
    ].join('\n');

    function hexToRgb(hex) {
        var h = String(hex).replace('#', '').trim();
        var full = h.length === 3 ? h.split('').map(function (c) { return c + c; }).join('') : (h + '000000').slice(0, 6);
        var n = parseInt(full, 16);
        if (isNaN(n)) return [0.1, 0.1, 0.12];
        return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
    }

    function isDarkTheme() {
        var root = document.documentElement;
        var t = root.getAttribute('data-theme');
        if (t === 'dark' || root.classList.contains('dark')) return true;
        if (t === 'light' || root.classList.contains('light')) return false;
        return window.matchMedia('(prefers-color-scheme: dark)').matches;
    }

    function compile(gl, type, src) {
        var sh = gl.createShader(type);
        if (!sh) return null;
        gl.shaderSource(sh, src);
        gl.compileShader(sh);
        if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) {
            console.warn('AsciiFluid: shader failed to compile\n', gl.getShaderInfoLog(sh));
            gl.deleteShader(sh);
            return null;
        }
        return sh;
    }

    function createProgram(gl, vs, fragSrc) {
        var fs = compile(gl, gl.FRAGMENT_SHADER, fragSrc);
        if (!fs) return null;
        var program = gl.createProgram();
        if (!program) { gl.deleteShader(fs); return null; }
        gl.attachShader(program, vs);
        gl.attachShader(program, fs);
        gl.linkProgram(program);
        if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
            console.warn('AsciiFluid: program failed to link\n', gl.getProgramInfoLog(program));
            gl.deleteProgram(program); gl.deleteShader(fs);
            return null;
        }
        return { program: program, fs: fs, locs: {} };
    }

    function createFBO(gl, w, h, filter) {
        var tex = gl.createTexture(), fbo = gl.createFramebuffer();
        if (!tex || !fbo) return null;
        gl.bindTexture(gl.TEXTURE_2D, tex);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, filter);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, filter);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, w, h, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
        gl.bindFramebuffer(gl.FRAMEBUFFER, fbo);
        gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, tex, 0);
        gl.bindFramebuffer(gl.FRAMEBUFFER, null);
        return { tex: tex, fbo: fbo, w: w, h: h };
    }

    function createDoubleFBO(gl, w, h, filter) {
        var a = createFBO(gl, w, h, filter), b = createFBO(gl, w, h, filter);
        if (!a || !b) return null;
        return {
            read: a, write: b,
            swap: function () { var t = this.read; this.read = this.write; this.write = t; }
        };
    }

    function buildAtlas(gl, charset) {
        var count = Math.max(charset.length, 1), size = 64;
        var c = document.createElement('canvas');
        c.width = size * count; c.height = size;
        var ctx = c.getContext('2d');
        if (!ctx) return null;
        ctx.fillStyle = '#000'; ctx.fillRect(0, 0, c.width, c.height);
        ctx.fillStyle = '#fff';
        ctx.font = '700 ' + Math.floor(size * 0.72) + 'px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
        ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
        for (var i = 0; i < count; i++) {
            var ch = charset.charAt(i) || ' ';
            if (ch === ' ') continue;
            ctx.fillText(ch, size * (i + 0.5), size * 0.55);
        }
        var tex = gl.createTexture();
        if (!tex) return null;
        gl.bindTexture(gl.TEXTURE_2D, tex);
        gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, 1);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, c);
        gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, 0);
        return { tex: tex, count: count };
    }

    function createAsciiFluid(canvas, initial) {
        var options = Object.assign({
            charset: DEFAULT_CHARSET, cellSize: 12, force: 1, dissipation: 0.05, brush: 0.55,
            animate: true, interactive: true, theme: 'auto', color: undefined, backgroundColor: undefined
        }, initial || {});

        var mouse = { x: 0.5, y: 0.5, dx: 0, dy: 0, moved: false, inside: false };
        var reduce = false;
        var currentCharset = '';

        var gl = canvas.getContext('webgl', {
            alpha: false, antialias: false, depth: false, stencil: false,
            powerPreference: 'high-performance', preserveDrawingBuffer: false
        });
        if (!gl) return null;

        var vs = compile(gl, gl.VERTEX_SHADER, VERT);
        if (!vs) return null;
        var splat = createProgram(gl, vs, FRAG_SPLAT);
        var advect = createProgram(gl, vs, FRAG_ADVECT);
        var divergence = createProgram(gl, vs, FRAG_DIVERGENCE);
        var pressure = createProgram(gl, vs, FRAG_PRESSURE);
        var gradient = createProgram(gl, vs, FRAG_GRADIENT);
        var display = createProgram(gl, vs, FRAG_DISPLAY);
        if (!splat || !advect || !divergence || !pressure || !gradient || !display) return null;

        var buf = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, buf);
        gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]), gl.STATIC_DRAW);

        function bindQuad(p) {
            gl.useProgram(p.program);
            var loc = gl.getAttribLocation(p.program, 'a_position');
            gl.enableVertexAttribArray(loc);
            gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
        }
        function L(p, name) {
            if (!(name in p.locs)) p.locs[name] = gl.getUniformLocation(p.program, name);
            return p.locs[name];
        }

        var SIM = 180;
        var velocity = createDoubleFBO(gl, SIM, SIM, gl.LINEAR);
        var dye = createDoubleFBO(gl, SIM, SIM, gl.LINEAR);
        var pressureFbo = createDoubleFBO(gl, SIM, SIM, gl.NEAREST);
        var divergenceFbo = createFBO(gl, SIM, SIM, gl.NEAREST);
        if (!velocity || !dye || !pressureFbo || !divergenceFbo) return null;

        var atlas = buildAtlas(gl, options.charset);
        if (!atlas) return null;
        currentCharset = options.charset;

        function blit(target) {
            if (target) { gl.bindFramebuffer(gl.FRAMEBUFFER, target.fbo); gl.viewport(0, 0, target.w, target.h); }
            else { gl.bindFramebuffer(gl.FRAMEBUFFER, null); gl.viewport(0, 0, canvas.width, canvas.height); }
            gl.drawArrays(gl.TRIANGLES, 0, 6);
        }
        function clearFbo(f, r, g, b) {
            gl.bindFramebuffer(gl.FRAMEBUFFER, f.fbo);
            gl.viewport(0, 0, f.w, f.h);
            gl.clearColor(r || 0, g || 0, b || 0, 1);
            gl.clear(gl.COLOR_BUFFER_BIT);
        }
        clearFbo(velocity.read, 0.5, 0.5, 0.5); clearFbo(velocity.write, 0.5, 0.5, 0.5);
        clearFbo(dye.read); clearFbo(dye.write);

        var raf = 0, running = true;
        var last = performance.now(), start = last;
        var parentEl = canvas.parentElement;

        function resize() {
            if (!parentEl) return;
            var dpr = Math.min(window.devicePixelRatio || 1, 2);
            var w = parentEl.clientWidth, h = parentEl.clientHeight;
            if (w <= 0 || h <= 0) return;
            canvas.width = Math.max(1, Math.floor(w * dpr));
            canvas.height = Math.max(1, Math.floor(h * dpr));
            canvas.style.width = w + 'px';
            canvas.style.height = h + 'px';
        }
        resize();
        var ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(resize) : null;
        if (ro && parentEl) ro.observe(parentEl);

        var mqReduce = window.matchMedia('(prefers-reduced-motion: reduce)');
        function onReduce() { reduce = mqReduce.matches; }
        onReduce();
        if (mqReduce.addEventListener) mqReduce.addEventListener('change', onReduce);

        function onPointer(e) {
            if (!options.interactive || !parentEl) return;
            var rect = parentEl.getBoundingClientRect();
            if (rect.width <= 0 || rect.height <= 0) return;
            var x = (e.clientX - rect.left) / rect.width;
            var y = 1 - (e.clientY - rect.top) / rect.height;
            mouse.inside = x >= 0 && x <= 1 && y >= 0 && y <= 1;
            mouse.dx = x - mouse.x; mouse.dy = y - mouse.y;
            mouse.x = x; mouse.y = y; mouse.moved = true;
        }
        function onLeave() { mouse.inside = false; }
        window.addEventListener('pointermove', onPointer, { passive: true });
        document.documentElement.addEventListener('pointerleave', onLeave, { passive: true });

        function tick(now) {
            if (!running) return;
            var dt = Math.min((now - last) / 1000, 0.033);
            last = now;
            var time = (now - start) / 1000;
            var p = options;

            if (p.charset !== currentCharset) {
                var next = buildAtlas(gl, p.charset);
                if (next) { gl.deleteTexture(atlas.tex); atlas = next; currentCharset = p.charset; }
            }

            var dark = p.theme === 'dark' ? true : p.theme === 'light' ? false : isDarkTheme();
            var ink = hexToRgb(p.color || (dark ? DARK.ink : LIGHT.ink));
            var paper = hexToRgb(p.backgroundColor || (dark ? DARK.paper : LIGHT.paper));
            var tx = 1 / SIM, ty = 1 / SIM;
            var aspect = canvas.width / Math.max(canvas.height, 1);
            var brushR = 0.00012 + Math.max(0.05, Math.min(1, p.brush)) * 0.0011;

            function splatTo(target, point, color, radius, isVel) {
                bindQuad(splat);
                gl.activeTexture(gl.TEXTURE0);
                gl.bindTexture(gl.TEXTURE_2D, target.read.tex);
                gl.uniform1i(L(splat, 'u_target'), 0);
                gl.uniform2f(L(splat, 'u_point'), point[0], point[1]);
                gl.uniform3f(L(splat, 'u_color'), color[0], color[1], color[2]);
                gl.uniform1f(L(splat, 'u_radius'), radius);
                gl.uniform1f(L(splat, 'u_aspect'), aspect);
                gl.uniform1f(L(splat, 'u_velocityField'), isVel ? 1 : 0);
                blit(target.write);
                target.swap();
            }

            if (p.interactive && mouse.moved && mouse.inside && !reduce) {
                var speed = Math.hypot(mouse.dx, mouse.dy);
                var strength = p.force * (18 + speed * 120);
                splatTo(velocity, [mouse.x, mouse.y], [mouse.dx * strength, mouse.dy * strength, 0], brushR, true);
                var dyeAmt = Math.min(1.4, 0.45 + speed * 8) * p.force;
                splatTo(dye, [mouse.x, mouse.y], [dyeAmt, 0, 0], brushR * 1.15, false);
                mouse.moved = false; mouse.dx = 0; mouse.dy = 0;
            }

            if (p.animate && !reduce && !mouse.inside) {
                splatTo(velocity,
                    [0.5 + Math.sin(time * 0.23) * 0.22, 0.5 + Math.cos(time * 0.19) * 0.18],
                    [Math.sin(time * 0.55) * 0.22, Math.cos(time * 0.42) * 0.22, 0], 0.0018, true);
            }

            if (!reduce) {
                bindQuad(advect);
                gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, velocity.read.tex);
                gl.uniform1i(L(advect, 'u_velocity'), 0);
                gl.activeTexture(gl.TEXTURE1); gl.bindTexture(gl.TEXTURE_2D, velocity.read.tex);
                gl.uniform1i(L(advect, 'u_source'), 1);
                gl.uniform2f(L(advect, 'u_texel'), tx, ty);
                gl.uniform1f(L(advect, 'u_dt'), dt);
                gl.uniform1f(L(advect, 'u_dissipation'), 1 - Math.min(0.18, p.dissipation * 2.5));
                gl.uniform1f(L(advect, 'u_velocityField'), 1);
                blit(velocity.write); velocity.swap();

                bindQuad(divergence);
                gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, velocity.read.tex);
                gl.uniform1i(L(divergence, 'u_velocity'), 0);
                gl.uniform2f(L(divergence, 'u_texel'), tx, ty);
                blit(divergenceFbo);

                clearFbo(pressureFbo.read, 0.5, 0.5, 0.5);
                clearFbo(pressureFbo.write, 0.5, 0.5, 0.5);
                bindQuad(pressure);
                for (var i = 0; i < 14; i++) {
                    gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, pressureFbo.read.tex);
                    gl.uniform1i(L(pressure, 'u_pressure'), 0);
                    gl.activeTexture(gl.TEXTURE1); gl.bindTexture(gl.TEXTURE_2D, divergenceFbo.tex);
                    gl.uniform1i(L(pressure, 'u_divergence'), 1);
                    gl.uniform2f(L(pressure, 'u_texel'), tx, ty);
                    blit(pressureFbo.write); pressureFbo.swap();
                }

                bindQuad(gradient);
                gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, pressureFbo.read.tex);
                gl.uniform1i(L(gradient, 'u_pressure'), 0);
                gl.activeTexture(gl.TEXTURE1); gl.bindTexture(gl.TEXTURE_2D, velocity.read.tex);
                gl.uniform1i(L(gradient, 'u_velocity'), 1);
                gl.uniform2f(L(gradient, 'u_texel'), tx, ty);
                blit(velocity.write); velocity.swap();

                bindQuad(advect);
                gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, velocity.read.tex);
                gl.uniform1i(L(advect, 'u_velocity'), 0);
                gl.activeTexture(gl.TEXTURE1); gl.bindTexture(gl.TEXTURE_2D, dye.read.tex);
                gl.uniform1i(L(advect, 'u_source'), 1);
                gl.uniform2f(L(advect, 'u_texel'), tx, ty);
                gl.uniform1f(L(advect, 'u_dt'), dt);
                gl.uniform1f(L(advect, 'u_dissipation'), 1 - Math.min(0.22, Math.max(0.02, p.dissipation)));
                gl.uniform1f(L(advect, 'u_velocityField'), 0);
                blit(dye.write); dye.swap();
            }

            bindQuad(display);
            gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, dye.read.tex);
            gl.uniform1i(L(display, 'u_dye'), 0);
            gl.activeTexture(gl.TEXTURE1); gl.bindTexture(gl.TEXTURE_2D, atlas.tex);
            gl.uniform1i(L(display, 'u_atlas'), 1);
            gl.uniform2f(L(display, 'u_resolution'), canvas.width, canvas.height);
            var cell = Math.max(7, p.cellSize) * Math.min(window.devicePixelRatio || 1, 2);
            gl.uniform2f(L(display, 'u_cell'), cell, cell);
            gl.uniform1f(L(display, 'u_charCount'), atlas.count);
            gl.uniform3f(L(display, 'u_ink'), ink[0], ink[1], ink[2]);
            gl.uniform3f(L(display, 'u_paper'), paper[0], paper[1], paper[2]);
            gl.uniform1f(L(display, 'u_time'), time);
            gl.uniform1f(L(display, 'u_animate'), p.animate && !reduce ? 1 : 0);
            blit(null);

            raf = requestAnimationFrame(tick);
        }
        raf = requestAnimationFrame(tick);

        return {
            setOptions: function (next) { options = Object.assign({}, options, next); },
            destroy: function () {
                running = false;
                cancelAnimationFrame(raf);
                if (ro) ro.disconnect();
                if (mqReduce.removeEventListener) mqReduce.removeEventListener('change', onReduce);
                window.removeEventListener('pointermove', onPointer);
                document.documentElement.removeEventListener('pointerleave', onLeave);
                [splat, advect, divergence, pressure, gradient, display].forEach(function (p) {
                    gl.deleteProgram(p.program); gl.deleteShader(p.fs);
                });
                gl.deleteShader(vs); gl.deleteBuffer(buf); gl.deleteTexture(atlas.tex);
                [velocity.read, velocity.write, dye.read, dye.write, pressureFbo.read, pressureFbo.write, divergenceFbo]
                    .forEach(function (f) { gl.deleteTexture(f.tex); gl.deleteFramebuffer(f.fbo); });
            }
        };
    }

    window.createAsciiFluid = createAsciiFluid;
    window.ASCII_FLUID_CHARSET = DEFAULT_CHARSET;
})();

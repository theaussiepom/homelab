"""Test-local checks for the Markdown forms used by the public documentation.

This is deliberately not an English or general Markdown validator. It checks
local destinations, GFM heading IDs, explicit anchors, fenced blocks and tables.
External links are counted, never fetched. A selected checkout can bind exact
GitHub revision links without adding network access or a runtime dependency.
"""
from collections import Counter
from html import unescape
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit


def without_code(text):
    return re.sub(r"(`+)(?:(?!\1).)*?\1", lambda m: " " * len(m[0]), text)


def table_cells(line):
    """GFM requires a pipe inside inline code to be escaped too."""
    return [part.strip() for part in re.split(r"(?<!\\)\|", line.strip().strip("|"))]


def slug(text):
    text = re.sub(r"!?\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = unescape(text).strip().lower().replace("`", "")
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


def _destination(value):
    value = value.strip()
    if value.startswith("<"):
        end = value.find(">")
        if end == -1:
            raise ValueError("unclosed angle destination")
        destination, tail = value[1:end], value[end + 1:].strip()
    else:
        parts = value.split(maxsplit=1)
        destination, tail = (parts[0], parts[1] if len(parts) > 1 else "") if parts else ("", "")
    if tail and not re.fullmatch(r'''(?:".*"|'.*'|\(.*\))''', tail):
        raise ValueError("unsupported link destination/title")
    return re.sub(r"\\([()\[\] ])", r"\1", destination)


def _balanced_end(text, start, opener, closer):
    depth = 1
    index = start + 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == opener:
            depth += 1
        elif text[index] == closer:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def parse_markdown(text):
    errors, anchors, links = [], set(), []
    headings, explicit = Counter(), set()
    visible = []
    fence = None
    text = re.sub(r"<!--.*?-->", lambda m: "\n" * m[0].count("\n"), text, flags=re.S)
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if fence:
            if match and match[1][0] == fence[0] and len(match[1]) >= fence[1] and not match[2].strip():
                fence = None
            visible.append((number, ""))
            continue
        if match:
            fence = (match[1][0], len(match[1]), number)
            visible.append((number, ""))
            continue
        # Indented code is not navigation. Lists in this suite use fenced code.
        if line.startswith("    ") or line.startswith("\t"):
            visible.append((number, ""))
            continue
        visible.append((number, line))
        for anchor in re.findall(r'''<a\s+(?:id|name)=["']([^"']+)["']\s*>''', without_code(line)):
            if anchor in anchors:
                errors.append(f"{number}: duplicate/colliding anchor #{anchor}")
            anchors.add(anchor)
            explicit.add(anchor)
        heading = re.match(r"^ {0,3}#{1,6}\s+(.+?)(?:\s+#+)?\s*$", line)
        if heading:
            base = slug(heading[1])
            identifier = base if not headings[base] else f"{base}-{headings[base]}"
            while identifier in anchors and identifier not in explicit:
                headings[base] += 1
                identifier = f"{base}-{headings[base]}"
            headings[base] += 1
            if identifier in explicit:
                errors.append(f"{number}: duplicate/colliding anchor #{identifier}")
            anchors.add(identifier)
    if fence:
        errors.append(f"{fence[2]}: unclosed fenced block")

    references = {}
    for number, line in visible:
        match = re.match(r"^ {0,3}\[([^\]]+)\]:\s*(.+)$", line)
        if match:
            label = " ".join(match[1].split()).casefold()
            if label in references:
                errors.append(f"{number}: duplicate reference definition [{label}]")
            try:
                references[label] = _destination(match[2])
            except ValueError as error:
                errors.append(f"{number}: {error}")
    for position, (number, line) in enumerate(visible):
        if re.match(r"^ {0,3}\[[^\]]+\]:", line):
            continue
        if position + 1 < len(visible) and line.lstrip().startswith("|"):
            separator = visible[position + 1][1]
            if separator.lstrip().startswith("|") and all(re.fullmatch(r":?-{3,}:?", cell) for cell in table_cells(separator)):
                width = len(table_cells(line))
                for row_number, row in visible[position + 1:]:
                    if not row.lstrip().startswith("|"):
                        break
                    if len(table_cells(row)) != width:
                        errors.append(f"{row_number}: table has {len(table_cells(row))} cells; expected {width}")
        clean = without_code(line)
        index = 0
        while index < len(clean):
            if clean[index] == "\\":
                index += 2
                continue
            if clean[index] != "[":
                index += 1
                continue
            end = _balanced_end(clean, index, "[", "]")
            if end is None:
                break
            label = " ".join(clean[index + 1:end].split()).casefold()
            after = end + 1
            if after < len(clean) and clean[after] == "(":
                close = _balanced_end(clean, after, "(", ")")
                if close is None:
                    errors.append(f"{number}: unclosed link destination")
                    break
                try:
                    # Code spans suppress prose links, but never rewrite a
                    # literal destination (including a malformed fragment).
                    links.append((number, _destination(line[after + 1:close])))
                except ValueError as error:
                    errors.append(f"{number}: {error}")
                index = close + 1
            elif after < len(clean) and clean[after] == "[":
                close = clean.find("]", after + 1)
                if close == -1:
                    errors.append(f"{number}: unclosed reference link")
                    break
                key = " ".join(clean[after + 1:close].split()).casefold() or label
                if key not in references:
                    errors.append(f"{number}: missing reference definition [{key}]")
                else:
                    links.append((number, references[key]))
                index = close + 1
            else:
                if label in references:
                    links.append((number, references[label]))
                index = after
    return anchors, links, errors


def _exact_file(root, path):
    """Catch wrong case on case-insensitive developer filesystems as on Linux."""
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    current = root
    for part in relative.parts:
        if not current.is_dir() or part not in {child.name for child in current.iterdir()}:
            return False
        current /= part
    return current.exists()


def check_documents(root, pages, checkout_links=None, entry_pages=None):
    root = Path(root).resolve()
    pages = sorted(set(Path(page).resolve() for page in pages))
    checkout_links = checkout_links or {}
    errors, parsed = [], {}
    edges = {page: set() for page in pages}
    external, checked = 0, 0
    if not pages:
        return {"pages": 0, "links": 0, "external_unverified": 0, "errors": ["empty documentation scope"]}

    def read(path):
        if path not in parsed:
            parsed[path] = parse_markdown(path.read_text())
            if path in pages:
                errors.extend(f"{path.relative_to(root)}:{error}" for error in parsed[path][2])
        return parsed[path]

    for page in pages:
        if not _exact_file(root, page) or not page.is_file():
            errors.append(f"{page.name}: missing documentation page")
            continue
        for number, destination in read(page)[1]:
            url = urlsplit(destination)
            location = f"{page.relative_to(root)}:{number}"
            boundary = root
            if url.scheme or url.netloc:
                match = re.fullmatch(r"/([^/]+/[^/]+)/(?:blob|tree)/([^/]+)/(.*)", url.path)
                key = (match[1], match[2]) if url.netloc == "github.com" and match else None
                if key not in checkout_links:
                    external += 1
                    continue
                boundary = Path(checkout_links[key]).resolve()
                target = (boundary / unquote(match[3])).resolve()
            else:
                if url.path.startswith("/"):
                    errors.append(f"{location}: use a repository-relative destination: {destination}")
                    continue
                target = (page.parent / unquote(url.path)).resolve() if url.path else page
            checked += 1
            if not _exact_file(boundary, target):
                errors.append(f"{location}: missing or wrong-case destination {destination}")
                continue
            graph_target = target / 'README.md' if target.is_dir() else target
            if graph_target in edges:
                edges[page].add(graph_target)
            fragment = unquote(url.fragment)
            if not fragment:
                continue
            if target.is_dir():
                target /= "README.md"
            if target.suffix.lower() == ".md" and target.is_file():
                if fragment not in read(target)[0]:
                    errors.append(f"{location}: missing anchor #{fragment} in {destination}")
            elif target.is_file() and re.fullmatch(r"L\d+(?:-L\d+)?", fragment):
                endpoints = [int(value) for value in re.findall(r"\d+", fragment)]
                if min(endpoints) < 1 or endpoints != sorted(endpoints) or max(endpoints) > len(target.read_text().splitlines()):
                    errors.append(f"{location}: invalid source line anchor {destination}")
            else:
                errors.append(f"{location}: unsupported anchor destination {destination}")
    entries = entry_pages if entry_pages is not None else [root / 'README.md' if root / 'README.md' in edges else pages[0]]
    pending = [Path(page).resolve() for page in entries]
    reachable = set()
    while pending:
        page = pending.pop()
        if page not in edges:
            errors.append(f"{page.name}: missing documentation entry page")
        elif page not in reachable:
            reachable.add(page)
            pending.extend(edges[page] - reachable)
    errors.extend(f"{page.relative_to(root)}: orphan documentation page" for page in sorted(set(pages) - reachable))
    return {"pages": len(pages), "links": checked, "external_unverified": external, "errors": sorted(set(errors))}

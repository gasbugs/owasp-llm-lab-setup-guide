"""Bounded publisher-only mutations of the P17 reference implementation."""

FAILURES = {
    'missing-log': 'exactly one current decision Log required',
    'duplicate-log': 'exactly one current decision Log required',
    'fixed-block-log': 'decision Log differs',
}


def inject(source, fault):
    """Change only Log emission; keep actual business, Trace and Counter intact."""
    if fault == 'missing-log':
        old, new = 'logger.info(', 'logger.debug('
    elif fault == 'duplicate-log':
        start = source.index('        logger.info(')
        end = source.index('        counter.labels(', start)
        old = source[start:end]
        new = old + old
    elif fault == 'fixed-block-log':
        old = "'decision': result['decision']"
        new = "'decision': 'block'"
    else:
        raise ValueError('unknown P17 fault')
    if source.count(old) != 1:
        raise ValueError('fault fixture no longer matches reference source')
    return source.replace(old, new)

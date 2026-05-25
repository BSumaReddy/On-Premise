"""Pagination helpers."""
import math


def pagination(request, data: list):
    """
    Slice *data* according to ?pageNumber and ?step query params.

    Returns:
        (page_data, total_pages, total_items)
    """
    page      = int(request.query_params.get("pageNumber", 1))
    step      = int(request.query_params.get("step", 10))
    total     = len(data)
    total_pages = math.ceil(total / step) if step else 1

    if total_pages <= 1 or page <= 1:
        start, end = 0, total
    else:
        start = (page - 1) * step
        end   = page * step

    return data[start:end], total_pages, total


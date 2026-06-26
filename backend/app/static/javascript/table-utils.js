/**
 * Client-Side Table Manager
 * Implements pagination, sorting, filtering via Web Workers 
 * to handle large datasets natively without framework overhead.
 */

class TableManager {
  /**
   * @param {Object} config
   * @param {string} config.tableId - CSS Selector for the <tbody>
   * @param {Array} config.data - Initial data array
   * @param {Function} config.renderRow - Function that returns HTML string for a row
   * @param {number} config.pageSize - Rows per page
   * @param {string} config.searchInputId - CSS selector for search input
   * @param {Array} config.searchKeys - Array of object keys to search
   */
  constructor(config) {
    this.tbody = document.querySelector(config.tableId);
    this.originalData = config.data || [];
    this.renderRow = config.renderRow;
    this.pageSize = config.pageSize || 25;
    this.currentPage = 1;
    this.filteredData = [...this.originalData];
    
    this.searchKeys = config.searchKeys || [];
    this.searchInput = config.searchInputId ? document.querySelector(config.searchInputId) : null;
    
    // Sort state
    this.sortCol = null;
    this.sortOrder = 'asc';

    this.worker = null;
    this.initWorker();
    
    if (this.searchInput) {
      this.initSearch();
    }
  }

  initWorker() {
    try {
      this.worker = new Worker('/static/javascript/worker-search.js');
      this.worker.onmessage = (e) => {
        if (e.data.status === 'success') {
          this.filteredData = e.data.result;
          this.currentPage = 1;
          this.render();
          
          // Announce to screen readers
          this.announceToA11y(`Found ${this.filteredData.length} results`);
        }
      };
    } catch (err) {
      console.warn("Web Workers not supported or path error, falling back to synchronous filtering", err);
    }
  }

  setData(newData) {
    this.originalData = newData;
    if (this.searchInput && this.searchInput.value) {
      this.filter(this.searchInput.value);
    } else {
      this.filteredData = [...this.originalData];
      this.render();
    }
  }

  initSearch() {
    let timeout = null;
    this.searchInput.addEventListener('input', (e) => {
      clearTimeout(timeout);
      timeout = setTimeout(() => {
        this.filter(e.target.value);
      }, 300); // 300ms debounce
    });
  }

  filter(query) {
    if (this.worker) {
      this.worker.postMessage({
        action: 'filter',
        query,
        data: this.originalData,
        keys: this.searchKeys
      });
    } else {
        const q = query.toLowerCase();
        this.filteredData = this.originalData.filter(row => {
          if (this.searchKeys.length === 0) {
            return Object.values(row).some(val => String(val).toLowerCase().includes(q));
          }
          return this.searchKeys.some(key => String(row[key] || "").toLowerCase().includes(q));
        });
        this.currentPage = 1;
        this.render();
    }
  }

  sort(key) {
    if (this.sortCol === key) {
      this.sortOrder = this.sortOrder === 'asc' ? 'desc' : 'asc';
    } else {
      this.sortCol = key;
      this.sortOrder = 'asc';
    }

    if (this.worker) {
      this.worker.postMessage({
        action: 'sort',
        sortBy: key,
        sortOrder: this.sortOrder,
        data: this.filteredData
      });
    } else {
        // Fallback sync sort
        this.filteredData.sort((a,b) => {
          let va = a[key] || "";
          let vb = b[key] || "";
          
          if (!isNaN(Number(va)) && !isNaN(Number(vb))) {
            return this.sortOrder === 'asc' ? Number(va) - Number(vb) : Number(vb) - Number(va);
          }
          
          const strA = String(va).toLowerCase();
          const strB = String(vb).toLowerCase();
          if (strA < strB) return this.sortOrder === 'asc' ? -1 : 1;
          if (strA > strB) return this.sortOrder === 'asc' ? 1 : -1;
          return 0;
        });
        this.render();
    }
    
    this.announceToA11y(`Table sorted by ${key} ${this.sortOrder}`);
  }

  render() {
    if (!this.tbody) return;

    if (this.filteredData.length === 0) {
      // Create empty state using our CSS system
      this.tbody.innerHTML = `
        <tr>
          <td colspan="100%">
            <div class="empty-state">
              <i class="fas fa-search" aria-hidden="true"></i>
              <h3>No results found</h3>
              <p>Try adjusting your search criteria</p>
            </div>
          </td>
        </tr>
      `;
      this.updatePaginationUI();
      return;
    }

    const start = (this.currentPage - 1) * this.pageSize;
    const end = start + this.pageSize;
    const pageData = this.filteredData.slice(start, end);

    let html = '';
    pageData.forEach((row, idx) => {
      html += this.renderRow(row, start + idx);
    });

    this.tbody.innerHTML = html;
    this.updatePaginationUI();
  }

  updatePaginationUI() {
    // Only implemented if a pagination container exists
    const container = document.getElementById(this.tbody.id + '-pagination');
    if (!container) return;

    const totalPages = Math.ceil(this.filteredData.length / this.pageSize) || 1;
    
    let html = `
      <div class="pagination-controls" style="display: flex; justify-content: space-between; align-items: center; padding: 1rem 1.25rem;">
        <span class="text-secondary" style="font-size: 0.85rem">
          Showing ${(this.currentPage - 1) * this.pageSize + (this.filteredData.length > 0 ? 1 : 0)} to 
          ${Math.min(this.currentPage * this.pageSize, this.filteredData.length)} of ${this.filteredData.length} entries
        </span>
        <div style="display: flex; gap: 0.5rem">
          <button class="btn btn-secondary btn-sm" ${this.currentPage === 1 ? 'disabled' : ''} id="prev-btn">Previous</button>
          <span style="display: flex; align-items: center; font-size: 0.9em; padding: 0 0.5rem">${this.currentPage} / ${totalPages}</span>
          <button class="btn btn-secondary btn-sm" ${this.currentPage === totalPages ? 'disabled' : ''} id="next-btn">Next</button>
        </div>
      </div>
    `;
    
    container.innerHTML = html;

    const prevBtn = container.querySelector('#prev-btn');
    const nextBtn = container.querySelector('#next-btn');

    if (prevBtn) {
      prevBtn.onclick = () => {
        if (this.currentPage > 1) {
          this.currentPage--;
          this.render();
        }
      };
    }

    if (nextBtn) {
      nextBtn.onclick = () => {
        if (this.currentPage < totalPages) {
          this.currentPage++;
          this.render();
        }
      };
    }
  }

  announceToA11y(message) {
    let region = document.getElementById('a11y-live-region');
    if (!region) {
      region = document.createElement('div');
      region.id = 'a11y-live-region';
      region.className = 'sr-only';
      region.setAttribute('aria-live', 'polite');
      document.body.appendChild(region);
    }
    region.textContent = message;
  }
}

window.TableManager = TableManager;

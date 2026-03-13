package main

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// --- Handlers: Managed Lists CRUD ---

func handleListManagedLists(ls *ManagedListStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, ls.List())
	}
}

func handleGetManagedList(ls *ManagedListStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		list, found := ls.Get(id)
		if !found {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "list not found"})
			return
		}
		writeJSON(w, http.StatusOK, list)
	}
}

func handleCreateManagedList(ls *ManagedListStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var list ManagedList
		if _, failed := decodeJSON(w, r, &list); failed {
			return
		}
		if err := validateManagedList(list); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "validation failed", Details: err.Error()})
			return
		}
		created, err := ls.Create(list)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to create list", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, created)
	}
}

func handleUpdateManagedList(ls *ManagedListStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		// Decode into a map first to detect which fields were sent.
		var raw map[string]json.RawMessage
		if _, failed := decodeJSON(w, r, &raw); failed {
			return
		}

		// Fetch existing to use as base for merge.
		existing, found := ls.Get(id)
		if !found {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "list not found"})
			return
		}

		// Reject updates to ipsum-sourced lists (read-only).
		if existing.Source == "ipsum" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "ipsum-sourced lists are read-only"})
			return
		}

		// Marshal existing to JSON, then overlay the incoming fields.
		base, _ := json.Marshal(existing)
		var merged ManagedList
		_ = json.Unmarshal(base, &merged)
		overlay, _ := json.Marshal(raw)
		_ = json.Unmarshal(overlay, &merged)

		if err := validateManagedList(merged); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "validation failed", Details: err.Error()})
			return
		}

		updated, found, err := ls.Update(id, merged)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "failed to update list", Details: err.Error()})
			return
		}
		if !found {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "list not found"})
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

func handleDeleteManagedList(ls *ManagedListStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		found, err := ls.Delete(id)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "failed to delete list", Details: err.Error()})
			return
		}
		if !found {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "list not found"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleRefreshManagedList(ls *ManagedListStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		updated, err := ls.RefreshURL(id)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "refresh failed", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

func handleExportManagedLists(ls *ManagedListStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, ls.Export())
	}
}

func handleImportManagedLists(ls *ManagedListStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var export ManagedListExport
		if _, failed := decodeJSON(w, r, &export); failed {
			return
		}
		if len(export.Lists) == 0 {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "no lists in import data"})
			return
		}
		// Validate all lists before importing.
		for i, list := range export.Lists {
			// Skip ipsum validation (system-managed).
			if list.Source == "ipsum" {
				continue
			}
			if err := validateManagedList(list); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{
					Error:   "validation failed",
					Details: "list " + strconv.Itoa(i) + ": " + err.Error(),
				})
				return
			}
		}
		if err := ls.Import(export.Lists); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to import lists", Details: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"imported": len(export.Lists)})
	}
}

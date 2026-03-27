#!/bin/bash
set -e
echo "=== VIREX2 Patch v2 ==="

cp app/api/persistence.py  ../app/api/persistence.py
cp app/api/routes.py       ../app/api/routes.py
cp app/api/security.py     ../app/api/security.py
cp app/ml/inference.py     ../app/ml/inference.py
cp app/auth/models.py      ../app/auth/models.py
cp app/auth/decorators.py  ../app/auth/decorators.py
cp app/templates/attack_history.html    ../app/templates/attack_history.html
cp app/templates/sidebar_component.html ../app/templates/sidebar_component.html
cp simple_app.py           ../simple_app.py

rm -f ../app/dashboard/routes_temp.py

# Add env vars if missing
if ! grep -q "ML_THRESHOLD_BLOCK" ../.env 2>/dev/null; then
    echo "" >> ../.env
    echo "ML_THRESHOLD_BLOCK=0.90"   >> ../.env
    echo "ML_THRESHOLD_MONITOR=0.70" >> ../.env
    echo "MAX_CONTENT_LENGTH=1048576" >> ../.env
    echo "Added ML vars to .env"
fi

echo "Done! Run: python verify_virex.py"

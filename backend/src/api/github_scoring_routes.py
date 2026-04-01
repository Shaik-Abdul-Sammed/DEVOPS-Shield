from fastapi import APIRouter, Depends, HTTPException
from ..services.github_scoring_service import github_scoring_service
from ..security.auth_manager import get_current_user

router = APIRouter()

@router.post("/connect")
async def connect_github(
    data: dict,
    current_user: dict = Depends(get_current_user)
):
    """
    Securely store GitHub connection details in the vault.
    """
    from ..security.secrets_manager import secret_vault, SecretType
    
    username = data.get("username")
    token = data.get("token")
    org = data.get("org")
    
    if not username or not token:
        raise HTTPException(status_code=400, detail="Username and token are required")
        
    secret_name = f"github_token_{current_user['user_id']}"
    # Store token encrypted
    secret_vault.store_secret(
        name=secret_name,
        value=token,
        secret_type=SecretType.SERVICE_CREDENTIAL
    )
    
    return {"status": "success", "message": "GitHub connection secured"}

@router.get("/score/{username}/{repo_name}")
async def get_repo_score(
    username: str, 
    repo_name: str, 
    current_user: dict = Depends(get_current_user)
):
    """
    Get the security and reputation score for a GitHub repository.
    """
    try:
        score_data = await github_scoring_service.calculate_repo_score(
            username, 
            repo_name, 
            user_id=current_user["user_id"]
        )
        return score_data
    except Exception as e:
        logger.error(f"Error in get_repo_score: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/account/{username}")
async def get_account_scores(
    username: str, 
    current_user: dict = Depends(get_current_user)
):
    """
    Get the security and reputation scores for all repositories associated with an account.
    """
    try:
        scores = await github_scoring_service.list_account_scores(
            username, 
            user_id=current_user["user_id"]
        )
        return scores
    except Exception as e:
        logger.error(f"Error in get_account_scores: {e}")
        raise HTTPException(status_code=500, detail=str(e))

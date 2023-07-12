from django.urls import path
from quizbase_quiz.views import QuestionListView, AnswerListView, ScoreView


urlpatterns = [
    path('questions/', QuestionListView.as_view(), 
         name='question-list'),

    path('answers/', AnswerListView.as_view(), name='amswers-list'),

    path('score/', ScoreView.as_view(), name='score'),

]